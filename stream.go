package coraza

import (
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type StreamRecorder struct {
	*ResponseWriterWrapper
	transaction         *engine.Transaction
	statusCode          int
	memoryBuffer        *bytes.Buffer // will be used by used for short responses
	fileWriter          *os.File      // will be used for heavy responses
	size                int64
	wroteHeader         bool

	stream  bool
	tmpPath string // used to store response tmp files
}

func (sr *StreamRecorder) WriteHeader(statusCode int) {
	if rr.wroteHeader {
		return
	}
	rr.statusCode = statusCode
	rr.wroteHeader = true

	sr.headerRecorder(sr.statusCode, sr.ResponseWriter.Header())
	var cl int64 // content length
	var ct string // content type
	for k, vr := range sr.ResponseWriter.Header() {
		if strings.Equals("content-length", k) {
			cl = strconv.ParseInt(vr[0], 10, 64)
		}else if strings.Equals("content-type", k) {
			ct = vr[0]
		}
	}
	// We dont want chunked responses or too heavy responses
	if cl == 0 || !utils.InSlice(sr.Transaction.ResponseMimes, ct){ // TODO include mimes
		rr.stream = true
	}

	// if not buffered, immediately write header
	if rr.stream {
		rr.ResponseWriter.WriteHeader(rr.statusCode)
	}
}

func (sr *StreamRecorder) Write(data []byte) (int, error) {
	sr.WriteHeader(http.StatusOK)
	var n int
	var err error
	if sr.stream {
		return sr.ResponseWriterWrapper.Write(data)
	}
	plen := sr.size
	if sr.size >= sr.transaction.ResponseBodyMemoryLimit {
		if sr.fileWriter == nil {
			sr.tmpPath = path.Join(sr.tmpPath, utils.RandomString(16))
			sr.fileWriter, err = os.Create(sr.tmpPath)
			if err != nil {
				return 0, err
			}
			sr.fileWriter.Write(sr.memoryBuffer.Bytes())
			sr.memoryBuffer.Flush()
		}
		sr.fileWriter.Write(data)
	} else {
		sr.memoryBuffer = copy(sr.memoryBuffer[plen:], data)
	}
	sr.size += int64(len(data))

	return n, err
}

// This function provides a mechanism to pick the most effective
// Buffering way for Coraza response body
// *io.Reader must be used with tx.ProcessResponseBody()
// string must be used with tx.ResponseBodyFromFile()
// Note this function will close the writter
func (sr *StreamRecorder) FileOrReader() (*io.Reader, string) {
	if sr.fileWriter == nil {
		// In case we don't use temporary files we use
		return bytes.NewReader(sr.memoryBuffer), ""
	} else {
		// Otherwise we will provide a path for the temporary file
		sr.fileWriter.Close()
		return nil, sr.tmpPath
	}
}
