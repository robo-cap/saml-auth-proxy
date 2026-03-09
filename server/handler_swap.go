package server

import (
	"net/http"
	"sync/atomic"
)

// SwapableHandler wraps an http.Handler and allows atomic swapping of the underlying handler.
// This enables seamless certificate reloading by atomically replacing all middleware
// components without disrupting in-flight requests.
type SwapableHandler struct {
	handler atomic.Value // stores *http.Handler
}

// NewSwapableHandler creates a new SwapableHandler with the given initial handler.
func NewSwapableHandler(h http.Handler) *SwapableHandler {
	sh := &SwapableHandler{}
	sh.handler.Store(&h)
	return sh
}

// Swap atomically replaces the current handler with a new one.
// This operation is lock-free and safe for concurrent use.
// In-flight requests will complete with the old handler; new requests will use the new handler.
func (h *SwapableHandler) Swap(newHandler http.Handler) {
	h.handler.Store(&newHandler)
}

// ServeHTTP implements the http.Handler interface by delegating to the current handler.
// The current handler is loaded atomically, ensuring consistent behavior during swaps.
func (h *SwapableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler := h.handler.Load().(*http.Handler)
	(*handler).ServeHTTP(w, r)
}
