// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"os"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func init() {
	// Register a fixed multipart body processor that overrides the default one
	// from Coraza. The fix ensures that temporary files are tracked in
	// FilesTmpNames before the file copy operation begins, so that they are
	// always cleaned up by tx.Close() even when the copy fails.
	//
	// In the upstream Coraza implementation the tracking call is placed after
	// io.Copy, which means that if io.Copy returns a non-io.ErrUnexpectedEOF
	// error (e.g. a write error) the file is created but never registered for
	// clean-up, leaving it on disk permanently.
	plugins.RegisterBodyProcessor("multipart", func() plugintypes.BodyProcessor {
		return &fixedMultipartBodyProcessor{}
	})
}

// mutableSingle is a duck-typing interface that matches the unexported
// Set method present on Coraza's internal *collections.Single type.
// Using a local interface avoids importing the internal package while still
// allowing us to set the value of Single-typed transaction variables.
type mutableSingle interface {
	Set(string)
}

// fixedMultipartBodyProcessor is a replacement for Coraza's built-in multipart
// body processor. It is functionally identical except that it registers each
// temporary file with the transaction's FilesTmpNames collection *before*
// copying the part data into it. This guarantees that tx.Close() will remove
// the file even when the copy operation fails partway through.
type fixedMultipartBodyProcessor struct{}

func (m *fixedMultipartBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	mimeType := options.Mime
	storagePath := options.StoragePath
	mediaType, params, err := mime.ParseMediaType(mimeType)
	if err != nil {
		setMutableSingle(v.MultipartStrictError(), "1")
		return err
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		return errors.New("not a multipart body")
	}

	mr := multipart.NewReader(reader, params["boundary"])
	totalSize := int64(0)
	filesCol := v.Files()
	filesTmpNamesCol := v.FilesTmpNames()
	fileSizesCol := v.FilesSizes()
	postCol := v.ArgsPost()
	filesNamesCol := v.FilesNames()
	headersNames := v.MultipartPartHeaders()

	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			setMutableSingle(v.MultipartStrictError(), "1")
			return err
		}
		partName := p.FormName()
		for key, values := range p.Header {
			for _, value := range values {
				headersNames.Add(partName, fmt.Sprintf("%s: %s", key, value))
			}
		}

		filename := multipartPartFileName(p)
		if filename != "" {
			var size int64
			seenUnexpectedEOF := false

			temp, err := os.CreateTemp(storagePath, "crzmp*")
			if err != nil {
				setMutableSingle(v.MultipartStrictError(), "1")
				return err
			}
			defer temp.Close()

			// Track the file BEFORE the copy so that tx.Close() can remove
			// it even when the copy fails with a non-ErrUnexpectedEOF error.
			// This is the key fix over the upstream Coraza implementation.
			filesTmpNamesCol.Add("", temp.Name())

			sz, err := io.Copy(temp, p)
			if err != nil {
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					setMutableSingle(v.MultipartStrictError(), "1")
					return err
				}
				seenUnexpectedEOF = true
			}
			size = sz

			totalSize += size
			filesCol.Add("", filename)
			fileSizesCol.SetIndex(filename, 0, fmt.Sprintf("%d", size))
			filesNamesCol.Add("", p.FormName())
			setMutableSingle(v.FilesCombinedSize(), fmt.Sprintf("%d", totalSize))
			if seenUnexpectedEOF {
				break
			}
		} else {
			data, err := io.ReadAll(p)
			if err != nil {
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					setMutableSingle(v.MultipartStrictError(), "1")
					return err
				}
			}
			totalSize += int64(len(data))
			postCol.Add(p.FormName(), string(data))
			setMutableSingle(v.FilesCombinedSize(), fmt.Sprintf("%d", totalSize))
			if errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
		}
	}
	return nil
}

func (m *fixedMultipartBodyProcessor) ProcessResponse(_ io.Reader, _ plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	return nil
}

// setMutableSingle sets a value on a collection.Single if the underlying
// implementation supports mutation (i.e. exposes a Set(string) method).
func setMutableSingle(s interface{ Get() string }, val string) {
	if ms, ok := s.(mutableSingle); ok {
		ms.Set(val)
	}
}

// multipartPartFileName returns the filename from a multipart part's
// Content-Disposition header, consistent with how Coraza resolves it.
func multipartPartFileName(p *multipart.Part) string {
	v := p.Header.Get("Content-Disposition")
	_, dispositionParams, err := mime.ParseMediaType(v)
	if err != nil {
		return ""
	}
	return dispositionParams["filename"]
}
