package standard_security_headers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServeHTTP(t *testing.T) {
	tests := []struct {
		name       string
		config     *Config
		assertFunc func(t *testing.T) http.Handler
	}{
		{
			name:   "default config",
			config: &Config{},
			assertFunc: func(t *testing.T) http.Handler {
				t.Helper()
				return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					hdr := getHeader(t, req, "X-Content-Type-Options")
					if hdr != "nosniff" {
						t.Fatalf("Header X-Content-Type-Options was blank, should be nosniff")
					}
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			handler, err := New(ctx, tt.assertFunc(t), tt.config, "security-headers-id-test")
			if err != nil {
				t.Fatalf("error creating new plugin instance: %+v", err)
			}
			recorder := httptest.NewRecorder()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/", nil)
			if err != nil {
				t.Fatalf("error with request: %+v", err)
			}

			handler.ServeHTTP(recorder, req)
		})
	}
}

func getHeader(t *testing.T, req *http.Request, headerName string) string {
	t.Helper()
	headerArr := req.Header[headerName]
	if len(headerArr) == 1 {
		return headerArr[0]
	}
	return ""
}
