// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	coraza "github.com/corazawaf/coraza/v3"
	"github.com/stretchr/testify/require"
)

// TestMultipartTempFilesCleanedUpAfterProcessPartial verifies that temporary
// multipart files (crzmp*) are removed by tx.Close() after a large multipart
// upload that triggers the ProcessPartial body-limit action.
func TestMultipartTempFilesCleanedUpAfterProcessPartial(t *testing.T) {
	uploadDir := t.TempDir()

	directives := fmt.Sprintf(`
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 131072
SecRequestBodyLimitAction ProcessPartial
SecUploadDir %s
`, uploadDir)

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	require.NoError(t, err)

	req := buildLargeMultipartRequest(t, 512*1024 /* 512 KB > 131072 byte limit */)

	tx := waf.NewTransaction()

	tx.ProcessConnection("127.0.0.1", 12345, "", 0)
	tx.ProcessURI("/upload", "POST", "HTTP/1.1")
	for k, vals := range req.Header {
		for _, v := range vals {
			tx.AddRequestHeader(k, v)
		}
	}
	tx.ProcessRequestHeaders()

	_, _, err = tx.ReadRequestBodyFrom(req.Body)
	require.NoError(t, err)

	// The temp file must exist after body processing but before tx.Close().
	midFiles, err := filepath.Glob(filepath.Join(uploadDir, "crzmp*"))
	require.NoError(t, err)
	require.NotEmpty(t, midFiles, "expected crzmp* temp file to exist after body processing")

	tx.ProcessLogging()
	require.NoError(t, tx.Close())

	// After tx.Close(), no crzmp* files should remain in uploadDir.
	afterFiles, err := filepath.Glob(filepath.Join(uploadDir, "crzmp*"))
	require.NoError(t, err)
	require.Empty(t, afterFiles, "crzmp* temp files must be cleaned up by tx.Close()")
}

// TestMultipartTempFilesCleanedUpWhenBodyProcessorFails verifies the core
// fix: even when the multipart body processing encounters an error after
// creating a temporary file, that file must be tracked in FilesTmpNames so
// that tx.Close() can remove it.
//
// The fixedMultipartBodyProcessor registers the temp file with FilesTmpNames
// *before* starting the copy operation, ensuring cleanup happens regardless of
// whether the copy succeeds or fails.
func TestMultipartTempFilesCleanedUpWhenBodyProcessorFails(t *testing.T) {
	uploadDir := t.TempDir()

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(fmt.Sprintf(`
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 131072
SecRequestBodyLimitAction ProcessPartial
SecUploadDir %s
`, uploadDir)))
	require.NoError(t, err)

	tx := waf.NewTransaction()

	// Build a truncated multipart body whose total length (512 KB) exceeds the
	// body limit (131072 bytes) but whose bytes are cut off in the middle of
	// the file-part content. ProcessPartial will buffer the first 131072 bytes
	// and then call ProcessRequestBody, which will encounter io.ErrUnexpectedEOF
	// when the multipart reader reaches the end of the truncated buffer.
	// The temporary file created for the file part must be tracked in
	// FilesTmpNames before the copy so that tx.Close() can remove it.
	req := buildTruncatedMultipartRequest(t, 512*1024, 300*1024 /* truncate after 300 KB */)

	tx.ProcessConnection("127.0.0.1", 12345, "", 0)
	tx.ProcessURI("/upload", "POST", "HTTP/1.1")
	for k, vals := range req.Header {
		for _, v := range vals {
			tx.AddRequestHeader(k, v)
		}
	}
	tx.ProcessRequestHeaders()

	_, _, err = tx.ReadRequestBodyFrom(req.Body)
	require.NoError(t, err)

	midFiles, err := filepath.Glob(filepath.Join(uploadDir, "crzmp*"))
	require.NoError(t, err)
	require.NotEmpty(t, midFiles, "expected crzmp* temp file to exist after body processing")

	tx.ProcessLogging()
	require.NoError(t, tx.Close())

	afterFiles, err := filepath.Glob(filepath.Join(uploadDir, "crzmp*"))
	require.NoError(t, err)
	require.Empty(t, afterFiles,
		"crzmp* temp files must be cleaned up by tx.Close() even when the body parser encountered an error")
}

// buildLargeMultipartRequest builds a complete multipart/form-data POST
// request whose file-part payload is fileSizeBytes large.
func buildLargeMultipartRequest(t *testing.T, fileSizeBytes int) *http.Request {
	t.Helper()

	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	fw, err := w.CreateFormFile("fupload", "large.txt")
	require.NoError(t, err)
	_, err = io.Copy(fw, strings.NewReader(strings.Repeat("X", fileSizeBytes)))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	req, err := http.NewRequest("POST", "/upload", &b)
	require.NoError(t, err)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}

// buildTruncatedMultipartRequest builds a multipart/form-data POST request
// whose body is truncated after truncateAt bytes, simulating a client that
// disconnects mid-upload or a body that exceeds a size limit.
func buildTruncatedMultipartRequest(t *testing.T, fileSizeBytes, truncateAt int) *http.Request {
	t.Helper()

	reader, contentType := buildTruncatedMultipartBody(t, fileSizeBytes, truncateAt)
	req, err := http.NewRequest("POST", "/upload", reader)
	require.NoError(t, err)
	req.Header.Set("Content-Type", contentType)
	return req
}

// buildTruncatedMultipartBody returns a reader containing the first
// truncateAt bytes of a complete multipart body together with the
// Content-Type header value.
func buildTruncatedMultipartBody(t *testing.T, fileSizeBytes, truncateAt int) (io.Reader, string) {
	t.Helper()

	var full bytes.Buffer
	w := multipart.NewWriter(&full)
	fw, err := w.CreateFormFile("fupload", "large.txt")
	require.NoError(t, err)
	_, err = io.Copy(fw, strings.NewReader(strings.Repeat("X", fileSizeBytes)))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	data := full.Bytes()
	if truncateAt > len(data) {
		truncateAt = len(data)
	}
	return bytes.NewReader(data[:truncateAt]), w.FormDataContentType()
}
