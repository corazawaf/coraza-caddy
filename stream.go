// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package coraza

import (
	"fmt"
	"io"
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza/v3/types"
)

type streamRecorder struct {
	*caddyhttp.ResponseWriterWrapper
	transaction types.Transaction
	statusCode  int
	wroteHeader bool

	stream bool
}

func (sr *streamRecorder) WriteHeader(statusCode int) {
	if sr.wroteHeader {
		return
	}
	sr.statusCode = statusCode
	sr.wroteHeader = true

	for k, vr := range sr.ResponseWriter.Header() {
		for _, v := range vr {
			sr.transaction.AddResponseHeader(k, v)
		}
	}
	sr.transaction.ProcessResponseHeaders(statusCode, "http/1.1")
	// we take care of unwanted responses
	if !sr.transaction.IsResponseBodyProcessable() {
		sr.stream = true
	}
	// We won't send response headers on stream if the transaction was interrupted
	// So the module can send an error page
	if !sr.transaction.IsInterrupted() && sr.stream {
		sr.ResponseWriter.WriteHeader(sr.statusCode)
		sr.stream = false
	}
}

func (sr *streamRecorder) Write(data []byte) (int, error) {
	sr.WriteHeader(http.StatusOK)
	if sr.transaction.IsInterrupted() {
		// We won't process the response body if the transaction was interrupted
		// There must be a way to stop receiving the buffer and avoid this wasted bandwidth
		return 0, nil
	}
	if sr.stream {
		return sr.ResponseWriterWrapper.Write(data)
	}

	interruption, n, err := sr.transaction.WriteResponseBody(data)
	if err != nil {
		return 0, fmt.Errorf("failed to append response body: %s", err.Error())
	}
	if interruption != nil {
		// Interruption raised while appending response body (e.g. limit reached)
		return 0, nil
	}

	return n, err
}

// Reader provides access to the buffered/inmemory response object
func (sr *streamRecorder) Reader() (io.Reader, error) {
	if sr.stream {
		return nil, nil
	}
	return sr.transaction.ResponseBodyReader()
}

// Buffered returns true if the response is stored inside the transaction
// IF false the response was already sent to the client
func (sr *streamRecorder) Buffered() bool {
	return !sr.stream
}

func (sr *streamRecorder) Status() int {
	return sr.statusCode
}

func newStreamRecorder(w http.ResponseWriter, tx types.Transaction) *streamRecorder {
	return &streamRecorder{
		ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
		transaction:           tx,
	}
}
