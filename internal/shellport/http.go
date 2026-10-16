package shellport

import (
	"net/http"
	"time"
)

// HTTPServer applies the production transport limits, including reads performed
// by net/http when it drains a body after a handler returns.
// Successful WebSocket hijacking clears the HTTP connection deadlines.
func (s *Server) HTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
}
