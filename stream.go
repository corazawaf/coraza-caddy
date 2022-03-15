package coraza

import (
	"io"
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza/v2"
)

type StreamRecorder struct {
	*caddyhttp.ResponseWriterWrapper
	transaction *coraza.Transaction
	statusCode  int
	wroteHeader bool

	stream bool
}

func (sr *StreamRecorder) WriteHeader(statusCode int) {
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
	if !sr.transaction.IsProcessableResponseBody() {
		sr.stream = true
	}
	// We won't send response headers on stream if the transaction was interrupted
	// So the module can send an error page
	if sr.transaction.Interruption == nil && sr.stream {
		sr.ResponseWriter.WriteHeader(sr.statusCode)
		sr.stream = false
	}
}

func (sr *StreamRecorder) Write(data []byte) (int, error) {
	sr.WriteHeader(http.StatusOK)
	if sr.transaction.Interruption != nil {
		// We won't process the response body if the transaction was interrupted
		// There must be a way to stop receiving the buffer and avoid this wasted bandwidth
		return 0, nil
	}
	if sr.stream {
		return sr.ResponseWriterWrapper.Write(data)
	}

	sr.transaction.ResponseBodyBuffer.Write(data)
	return len(data), nil
}

// Reader provides access to the buffered/inmemory response object
func (sr *StreamRecorder) Reader() (io.Reader, error) {
	if sr.stream {
		return nil, nil
	}
	return sr.transaction.ResponseBodyBuffer.Reader()
}

// Buffered returns true if the response is stored inside the transaction
// IF false the response was already sent to the client
func (sr *StreamRecorder) Buffered() bool {
	return !sr.stream
}

func (sr *StreamRecorder) Status() int {
	return sr.statusCode
}

func NewStreamRecorder(w http.ResponseWriter, tx *coraza.Transaction) *StreamRecorder {
	return &StreamRecorder{
		ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
		transaction:           tx,
	}
}
