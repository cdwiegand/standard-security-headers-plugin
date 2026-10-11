package standard_security_headers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServeHTTP(t *testing.T) {
	tests := []struct {
		name           string
		config         func() *Config
		backendHeaders map[string]string
		writeHeader    bool
		expected       map[string]string
		absent         []string
	}{
		{
			name:           "defaults on html response",
			config:         CreateConfig,
			backendHeaders: map[string]string{"Content-Type": "text/html; charset=utf-8"},
			writeHeader:    true,
			expected: map[string]string{
				Header_XFrameOptions:           Default_XFrameOptions,
				Header_ContentTypeOptions:      "nosniff",
				Header_XssProtection:           "1",
				Header_ReferrerPolicy:          Default_ReferrerPolicy,
				Header_StrictTransportSecurity: Default_StrictTransportSecurity,
			},
			absent: []string{Header_ContentSecurityPolicy, Header_PermissionsPolicy},
		},
		{
			name:           "defaults on non-html response",
			config:         CreateConfig,
			backendHeaders: map[string]string{"Content-Type": "application/json"},
			writeHeader:    true,
			expected: map[string]string{
				Header_XFrameOptions:      Default_XFrameOptions,
				Header_ContentTypeOptions: "nosniff",
				Header_XssProtection:      "1",
			},
		},
		{
			name:           "defaults applied when backend only calls Write",
			config:         CreateConfig,
			backendHeaders: map[string]string{},
			writeHeader:    false,
			expected:       map[string]string{Header_XFrameOptions: Default_XFrameOptions},
		},
		{
			name:   "exposing headers are removed",
			config: CreateConfig,
			backendHeaders: map[string]string{
				"Server":       "Apache/2.4",
				"X-Powered-By": "PHP/8.3",
			},
			writeHeader: true,
			absent:      []string{"Server", "X-Powered-By"},
		},
		{
			name: "exposing headers kept when sanitizing is off",
			config: func() *Config {
				c := CreateConfig()
				c.SanitizeExposingHeaders = false
				return c
			},
			backendHeaders: map[string]string{"Server": "Apache/2.4"},
			writeHeader:    true,
			expected:       map[string]string{"Server": "Apache/2.4"},
		},
		{
			name:   "backend value wins over default",
			config: CreateConfig,
			backendHeaders: map[string]string{
				Header_XFrameOptions:         "DENY",
				Header_ContentSecurityPolicy: "default-src 'self'",
			},
			writeHeader: true,
			expected: map[string]string{
				Header_XFrameOptions:         "DENY",
				Header_ContentSecurityPolicy: "default-src 'self'",
			},
		},
		{
			name:           "force value wins over backend",
			config:         CreateConfig,
			backendHeaders: map[string]string{Header_XssProtection: "1; mode=block"},
			writeHeader:    true,
			expected:       map[string]string{Header_XssProtection: "1"},
		},
		{
			name: "force disable removes header",
			config: func() *Config {
				c := CreateConfig()
				c.ForceHeaders.XFrameOptions = DisableValue
				return c
			},
			backendHeaders: map[string]string{Header_XFrameOptions: "DENY"},
			writeHeader:    true,
			absent:         []string{Header_XFrameOptions},
		},
		{
			name: "default disable adds nothing but keeps backend value",
			config: func() *Config {
				c := CreateConfig()
				c.DefaultHeaders.StrictTransportSecurity = DisableValue
				c.DefaultHeaders.ReferrerPolicy = DisableValue
				return c
			},
			backendHeaders: map[string]string{Header_ReferrerPolicy: "no-referrer"},
			writeHeader:    true,
			expected:       map[string]string{Header_ReferrerPolicy: "no-referrer"},
			absent:         []string{Header_StrictTransportSecurity},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				for k, v := range tt.backendHeaders {
					rw.Header().Set(k, v)
				}
				if tt.writeHeader {
					rw.WriteHeader(http.StatusOK)
				}
				_, _ = rw.Write([]byte("ok"))
			})

			handler, err := New(ctx, next, tt.config(), "security-headers-id-test")
			if err != nil {
				t.Fatalf("error creating new plugin instance: %+v", err)
			}
			recorder := httptest.NewRecorder()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/", nil)
			if err != nil {
				t.Fatalf("error with request: %+v", err)
			}

			handler.ServeHTTP(recorder, req)

			headers := recorder.Result().Header
			for name, want := range tt.expected {
				if got := headers.Values(name); len(got) != 1 || got[0] != want {
					t.Errorf("header %s = %q, want [%q]", name, got, want)
				}
			}
			for _, name := range tt.absent {
				if got := headers.Values(name); len(got) != 0 {
					t.Errorf("header %s = %q, want absent", name, got)
				}
			}
		})
	}
}

func TestFlushAppliesHeaders(t *testing.T) {
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.(http.Flusher).Flush()
	})
	handler, err := New(context.Background(), next, CreateConfig(), "security-headers-id-test")
	if err != nil {
		t.Fatalf("error creating new plugin instance: %+v", err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))

	if got := recorder.Result().Header.Get(Header_XFrameOptions); got != Default_XFrameOptions {
		t.Errorf("header %s = %q, want %q", Header_XFrameOptions, got, Default_XFrameOptions)
	}
}
