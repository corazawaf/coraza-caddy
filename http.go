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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/types"
	"go.uber.org/zap"
)

func processRequest(tx types.Transaction, r *http.Request, logger *zap.Logger) (*types.Interruption, error) {
	// first we parse the r.RemoteAddr, it could be an IP or an IP:PORT or a [IP]:PORT
	remoteAddr := r.RemoteAddr
	remotePort := ""
	if strings.Contains(remoteAddr, ":") {
		remoteAddr, remotePort, _ = net.SplitHostPort(remoteAddr)
	}
	rPort, err := strconv.Atoi(remotePort)
	if err != nil {
		rPort = 0
	}

	tx.ProcessConnection(remoteAddr, rPort, "", 0)
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
	for k, v := range r.Header {
		tx.AddRequestHeader(k, v[0])
	}
	tx.AddRequestHeader("Host", r.Host)
	serverName, err := parseServerName(r.Host)
	if err != nil {
		// Even if an error is raised, serverName is still populated
		logger.Debug("Failed to parse server name from host", zap.String("host", r.Host), zap.Error(err))
	}
	tx.SetServerName(serverName)
	if it := tx.ProcessRequestHeaders(); it != nil {
		return it, nil
	}
	if r.Body != nil && r.Body != http.NoBody {
		it, _, err := tx.ReadRequestBodyFrom(r.Body)
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

		body := io.MultiReader(rbr, r.Body)
		// req.Body is transparently reinizialied with a new io.ReadCloser.
		// The http handler will be able to read it.
		// Prior to Go 1.19 NopCloser does not implement WriterTo if the reader implements it.
		// - https://github.com/golang/go/issues/51566
		// - https://tip.golang.org/doc/go1.19#minor_library_changes
		// This avoid errors like "failed to process request: malformed chunked encoding" when
		// using io.Copy.
		// In Go 1.19 we just do `req.Body = io.NopCloser(reader)`
		if rwt, ok := body.(io.WriterTo); ok {
			r.Body = struct {
				io.Reader
				io.WriterTo
				io.Closer
			}{body, rwt, r.Body}
		} else {
			r.Body = struct {
				io.Reader
				io.Closer
			}{body, r.Body}
		}
	}
	return tx.ProcessRequestBody()
}

// parseServerName parses r.Host in order to retrieve the virtual host.
func parseServerName(host string) (string, error) {
	serverName, _, err := net.SplitHostPort(host)
	if err != nil {
		// missing port or bad format
		err = errors.New(fmt.Sprintf("failed to parse server name from authority %q, %v", host, err))
		serverName = host
	}
	// anyways serverName is returned
	return serverName, err
}
