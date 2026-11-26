package adapter

import (
	"context"
	"net/http"
)

type pathFilterKey struct{}

func WithPathFilter(ctx context.Context, filter func(*http.Request) bool) context.Context {
	return context.WithValue(ctx, pathFilterKey{}, filter)
}

func RejectProbe(ctx context.Context, w http.ResponseWriter, r *http.Request) bool {
	filter, _ := ctx.Value(pathFilterKey{}).(func(*http.Request) bool)
	if filter == nil || !filter(r) {
		return false
	}
	w.WriteHeader(http.StatusNotFound)
	return true
}
