// Copyright 2023 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/corazawaf/coraza/v3/types"
)

// Copied from https://github.com/corazawaf/coraza/blob/main/http/middleware.go

func processRequest(tx types.Transaction, req *http.Request) (*types.Interruption, error) {

	client, cport := getClientAddress(req)

	var in *types.Interruption
	// There is no socket access in the request object, so we neither know the server client nor port.
	tx.ProcessConnection(client, cport, "", 0)
	tx.ProcessURI(req.URL.String(), req.Method, req.Proto)
	for k, vr := range req.Header {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}

	// Host will always be removed from req.Headers() and promoted to the
	// Request.Host field, so we manually add it
	if req.Host != "" {
		tx.AddRequestHeader("Host", req.Host)
		// This connector relies on the host header (now host field) to populate ServerName
		tx.SetServerName(parseServerName(req.Host))
	}

	// Transfer-Encoding header is removed by go/http
	// See https://github.com/golang/go/blob/ada0eec8277449ecd6383c86bc2e5fe7e7058fc7/src/net/http/transfer.go#L631
	// We manually add it to make rules relying on it work (E.g. CRS rule 920171)
	if req.TransferEncoding != nil {
		tx.AddRequestHeader("Transfer-Encoding", req.TransferEncoding[0])
	}

	in = tx.ProcessRequestHeaders()
	if in != nil {
		return in, nil
	}

	if tx.IsRequestBodyAccessible() {
		// We only do body buffering if the transaction requires request
		// body inspection, otherwise we just let the request follow its
		// regular flow.
		if req.Body != nil && req.Body != http.NoBody {
			it, _, err := tx.ReadRequestBodyFrom(req.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to append request body: %s", err.Error())
			}

			if it != nil {
				return it, nil
			}

			rbr, err := tx.RequestBodyReader()
			if err != nil {
				return nil, fmt.Errorf("failed to get the request body: %s", err.Error())
			}

			// Adds all remaining bytes beyond the coraza limit to its buffer
			// It happens when the partial body has been processed and it did not trigger an interruption
			body := io.MultiReader(rbr, req.Body)
			// req.Body is transparently reinizialied with a new io.ReadCloser.
			// The http handler will be able to read it.
			// Prior to Go 1.19 NopCloser does not implement WriterTo if the reader implements it.
			// - https://github.com/golang/go/issues/51566
			// - https://tip.golang.org/doc/go1.19#minor_library_changes
			// This avoid errors like "failed to process request: malformed chunked encoding" when
			// using io.Copy.
			// In Go 1.19 we just do `req.Body = io.NopCloser(reader)`
			if rwt, ok := body.(io.WriterTo); ok {
				req.Body = struct {
					io.Reader
					io.WriterTo
					io.Closer
				}{body, rwt, req.Body}
			} else {
				req.Body = struct {
					io.Reader
					io.Closer
				}{body, req.Body}
			}
		}
	}

	return tx.ProcessRequestBody()
}

// parseServerName parses r.Host in order to retrieve the virtual host.
func parseServerName(host string) string {
	serverName, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	// anyways serverName is returned
	return serverName
}
