package standard_security_headers

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
)

// DisableValue removes the header: as a force value it always strips the header from the response,
// as a default value it means no default is added (a value set by the backend still passes through).
const DisableValue = "-"

const (
	Header_XFrameOptions                    = "X-Frame-Options"
	Default_XFrameOptions                   = "SAMEORIGIN"
	Force_XFrameOptions                     = ""
	Header_ContentTypeOptions               = "X-Content-Type-Options"
	Default_ContentTypeOptions              = "nosniff"
	Force_ContentTypeOptions                = "nosniff"
	Header_XssProtection                    = "X-XSS-Protection"
	Default_XssProtection                   = "1"
	Force_XssProtection                     = "1"
	Header_ReferrerPolicy                   = "Referrer-Policy"
	Default_ReferrerPolicy                  = "strict-origin-when-cross-origin"
	Force_ReferrerPolicy                    = ""
	Header_StrictTransportSecurity          = "Strict-Transport-Security"
	Default_StrictTransportSecurity         = "max-age=63072000; includeSubDomains"
	Force_StrictTransportSecurity           = ""
	Header_ContentSecurityPolicy            = "Content-Security-Policy"
	Default_ContentSecurityPolicy           = ""
	Force_ContentSecurityPolicy             = ""
	Header_ContentSecurityPolicyReportOnly  = "Content-Security-Policy-Report-Only"
	Default_ContentSecurityPolicyReportOnly = ""
	Force_ContentSecurityPolicyReportOnly   = ""
	Header_CrossOriginOpenerPolicy          = "Cross-Origin-Opener-Policy"
	Default_CrossOriginOpenerPolicy         = ""
	Force_CrossOriginOpenerPolicy           = ""
	Header_CrossOriginEmbedderPolicy        = "Cross-Origin-Embedder-Policy"
	Default_CrossOriginEmbedderPolicy       = ""
	Force_CrossOriginEmbedderPolicy         = ""
	Header_CrossOriginResourcePolicy        = "Cross-Origin-Resource-Policy"
	Default_CrossOriginResourcePolicy       = ""
	Force_CrossOriginResourcePolicy         = ""
	Header_PermissionsPolicy                = "Permissions-Policy"
	Default_PermissionsPolicy               = ""
	Force_PermissionsPolicy                 = ""
)

// Config the plugin configuration.
type Config struct {
	SanitizeExposingHeaders bool          `json:"sanitizeExposingHeaders"`
	DefaultHeaders          ConfigHeaders `json:"defaultHeaders"`
	ForceHeaders            ConfigHeaders `json:"forceHeaders"`
}

type ConfigHeaders struct {
	XFrameOptions                   string `json:"xframeOptions"`
	ContentTypeOptions              string `json:"contentTypeOptions"`
	XssProtection                   string `json:"xssProtection"`
	ReferrerPolicy                  string `json:"referrerPolicy"`
	StrictTransportSecurity         string `json:"strictTransportSecurity"`
	ContentSecurityPolicy           string `json:"contentSecurityPolicy"`
	ContentSecurityPolicyReportOnly string `json:"contentSecurityPolicyReportOnly"`
	CrossOriginOpenerPolicy         string `json:"crossOriginOpenerPolicy"`
	CrossOriginEmbedderPolicy       string `json:"crossOriginEmbedderPolicy"`
	CrossOriginResourcePolicy       string `json:"crossOriginResourcePolicy"`
	PermissionsPolicy               string `json:"permissionsPolicy"`
}

// CreateConfig creates the DEFAULT plugin configuration - no access to config yet!
func CreateConfig() *Config {
	defaultHeaders := ConfigHeaders{
		XFrameOptions:                   Default_XFrameOptions,
		ContentTypeOptions:              Default_ContentTypeOptions,
		XssProtection:                   Default_XssProtection,
		ReferrerPolicy:                  Default_ReferrerPolicy,
		StrictTransportSecurity:         Default_StrictTransportSecurity,
		ContentSecurityPolicy:           Default_ContentSecurityPolicy,
		ContentSecurityPolicyReportOnly: Default_ContentSecurityPolicyReportOnly,
		CrossOriginOpenerPolicy:         Default_CrossOriginOpenerPolicy,
		CrossOriginEmbedderPolicy:       Default_CrossOriginEmbedderPolicy,
		CrossOriginResourcePolicy:       Default_CrossOriginResourcePolicy,
		PermissionsPolicy:               Default_PermissionsPolicy,
	}

	forceHeaders := ConfigHeaders{
		XFrameOptions:                   Force_XFrameOptions,
		ContentTypeOptions:              Force_ContentTypeOptions,
		XssProtection:                   Force_XssProtection,
		ReferrerPolicy:                  Force_ReferrerPolicy,
		StrictTransportSecurity:         Force_StrictTransportSecurity,
		ContentSecurityPolicy:           Force_ContentSecurityPolicy,
		ContentSecurityPolicyReportOnly: Force_ContentSecurityPolicyReportOnly,
		CrossOriginOpenerPolicy:         Force_CrossOriginOpenerPolicy,
		CrossOriginEmbedderPolicy:       Force_CrossOriginEmbedderPolicy,
		CrossOriginResourcePolicy:       Force_CrossOriginResourcePolicy,
		PermissionsPolicy:               Force_PermissionsPolicy,
	}

	return &Config{
		SanitizeExposingHeaders: true,
		DefaultHeaders:          defaultHeaders,
		ForceHeaders:            forceHeaders,
	}
}

// StandardSecurityPlugin header
type StandardSecurityPlugin struct {
	Config *Config
	name   string
	next   http.Handler
}

// New created a new plugin, with a config that's been set (possibly) by the admin
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		return nil, fmt.Errorf("config can not be nil")
	}

	plugin := &StandardSecurityPlugin{
		Config: config,
		next:   next,
		name:   name,
	}

	return plugin, nil
}

func (t *StandardSecurityPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// headers can only be adjusted once the backend has set its own, so wait until they are written
	t.next.ServeHTTP(&responseWriter{ResponseWriter: rw, plugin: t}, req)
}

func (t *StandardSecurityPlugin) applyHeaders(headers http.Header) {
	if t.Config.SanitizeExposingHeaders {
		for _, header := range badHeaders() {
			headers.Del(header)
		}
	}

	d := t.Config.DefaultHeaders
	f := t.Config.ForceHeaders
	handleHeader(headers, Header_XFrameOptions, d.XFrameOptions, f.XFrameOptions)
	handleHeader(headers, Header_ContentTypeOptions, d.ContentTypeOptions, f.ContentTypeOptions)
	handleHeader(headers, Header_XssProtection, d.XssProtection, f.XssProtection)
	handleHeader(headers, Header_ReferrerPolicy, d.ReferrerPolicy, f.ReferrerPolicy)
	handleHeader(headers, Header_StrictTransportSecurity, d.StrictTransportSecurity, f.StrictTransportSecurity)
	handleHeader(headers, Header_ContentSecurityPolicy, d.ContentSecurityPolicy, f.ContentSecurityPolicy)
	handleHeader(headers, Header_ContentSecurityPolicyReportOnly, d.ContentSecurityPolicyReportOnly, f.ContentSecurityPolicyReportOnly)
	handleHeader(headers, Header_CrossOriginOpenerPolicy, d.CrossOriginOpenerPolicy, f.CrossOriginOpenerPolicy)
	handleHeader(headers, Header_CrossOriginEmbedderPolicy, d.CrossOriginEmbedderPolicy, f.CrossOriginEmbedderPolicy)
	handleHeader(headers, Header_CrossOriginResourcePolicy, d.CrossOriginResourcePolicy, f.CrossOriginResourcePolicy)
	handleHeader(headers, Header_PermissionsPolicy, d.PermissionsPolicy, f.PermissionsPolicy)
}

func handleHeader(headers http.Header, headerName string, defaultValue string, forceValue string) {
	if forceValue == DisableValue {
		headers.Del(headerName)
		return
	}

	if forceValue != "" {
		headers.Set(headerName, forceValue)
		return
	}

	if defaultValue != "" && defaultValue != DisableValue && headers.Get(headerName) == "" {
		headers.Set(headerName, defaultValue)
	}
}

// responseWriter applies the security headers just before the backend's response headers are sent.
type responseWriter struct {
	http.ResponseWriter
	plugin      *StandardSecurityPlugin
	wroteHeader bool
}

func (w *responseWriter) WriteHeader(code int) {
	// 1xx informational responses (e.g. 103 Early Hints) are followed by the real response
	if !w.wroteHeader && (code < 100 || code >= 200) {
		w.wroteHeader = true
		w.plugin.applyHeaders(w.ResponseWriter.Header())
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *responseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("%T does not implement http.Hijacker", w.ResponseWriter)
	}
	return hijacker.Hijack()
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *responseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func badHeaders() []string {
	return []string{
		// used from https://owasp.org/www-project-secure-headers/ci/headers_remove.json
		// "last_update_utc": "2024-10-18 18:07:18",
		"$wsep",
		"Host-Header",
		"K-Proxy-Request",
		"Liferay-Portal",
		"OracleCommerceCloud-Version",
		"Pega-Host",
		"Powered-By",
		"Product",
		"Server",
		"SourceMap",
		"X-AspNet-Version",
		"X-AspNetMvc-Version",
		"X-Atmosphere-error",
		"X-Atmosphere-first-request",
		"X-Atmosphere-tracking-id",
		"X-B3-ParentSpanId",
		"X-B3-Sampled",
		"X-B3-SpanId",
		"X-B3-TraceId",
		"X-BEServer",
		"X-Backside-Transport",
		"X-CF-Powered-By",
		"X-CMS",
		"X-CalculatedBETarget",
		"X-Cocoon-Version",
		"X-Content-Encoded-By",
		"X-DiagInfo",
		"X-Envoy-Attempt-Count",
		"X-Envoy-External-Address",
		"X-Envoy-Internal",
		"X-Envoy-Original-Dst-Host",
		"X-Envoy-Upstream-Service-Time",
		"X-FEServer",
		"X-Framework",
		"X-Generated-By",
		"X-Generator",
		"X-Jitsi-Release",
		"X-Joomla-Version",
		"X-Kubernetes-PF-FlowSchema-UI",
		"X-Kubernetes-PF-PriorityLevel-UID",
		"X-LiteSpeed-Cache",
		"X-LiteSpeed-Purge",
		"X-LiteSpeed-Tag",
		"X-LiteSpeed-Vary",
		"X-Litespeed-Cache-Control",
		"X-Mod-Pagespeed",
		"X-Nextjs-Cache",
		"X-Nextjs-Matched-Path",
		"X-Nextjs-Page",
		"X-Nextjs-Redirect",
		"X-OWA-Version",
		"X-Old-Content-Length",
		"X-OneAgent-JS-Injection",
		"X-Page-Speed",
		"X-Php-Version",
		"X-Powered-By",
		"X-Powered-By-Plesk",
		"X-Powered-CMS",
		"X-Redirect-By",
		"X-Server-Powered-By",
		"X-SourceFiles",
		"X-SourceMap",
		"X-Turbo-Charged-By",
		"X-Umbraco-Version",
		"X-Varnish-Backend",
		"X-Varnish-Server",
		"X-dtAgentId",
		"X-dtHealthCheck",
		"X-dtInjectedServlet",
		"X-ruxit-JS-Agent",
		// partial list from https://webhint.io/docs/user-guide/hints/hint-no-disallowed-headers/
		"X-Runtime",
		"X-Version",
	}
}
