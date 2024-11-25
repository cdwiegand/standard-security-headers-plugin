package standard_security_headers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

const (
	Header_XFrameOptions                    = "X-Frame-Options"
	Default_XFrameOptions                   = "SAMEORIGIN"
  Force_XFrameOptions                     = ""
	Header_ContentTypeOptions               = "X-Content-Type-Options"
	Default_ContentTypeOptions              = "nosniff"
	Force_ContentTypeOptions              = "nosniff"
	Header_XssProtection                    = "X-XSS-Protection"
	Default_XssProtection                   = "1; mode=block"
	Force_XssProtection                   = "1; mode=block"
	Header_ReferrerPolicy                   = "Referrer-Policy"
	Default_ReferrerPolicy                  = "strict-origin-when-cross-origin"
	Force_ReferrerPolicy                  = ""
	Header_StrictTransportSecurity          = "Strict-Transport-Security"
	Default_StrictTransportSecurity         = "max-age=63072000; includeSubDomains; preload"
	Force_StrictTransportSecurity         = ""
	Header_ContentSecurityPolicy            = "Content-Security-Policy"
	Default_ContentSecurityPolicy           = ""
	Force_ContentSecurityPolicy           = ""
	Header_ContentSecurityPolicyReportOnly  = "Content-Security-Policy-Report-Only"
	Default_ContentSecurityPolicyReportOnly = ""
	Force_ContentSecurityPolicyReportOnly = ""
	Header_CrossOriginOpenerPolicy          = "Cross-Origin-Opener-Policy"
	Default_CrossOriginOpenerPolicy         = ""
	Force_CrossOriginOpenerPolicy         = ""
	Header_CrossOriginEmbedderPolicy        = "Cross-Origin-Embedder-Policy"
	Default_CrossOriginEmbedderPolicy       = ""
	Force_CrossOriginEmbedderPolicy       = ""
	Header_CrossOriginResourcePolicy        = "Cross-Origin-Resource-Policy"
	Default_CrossOriginResourcePolicy       = ""
	Force_CrossOriginResourcePolicy       = ""
	Header_PermissionsPolicy                = "Permissions-Policy"
	Default_PermissionsPolicy               = ""
	Force_PermissionsPolicy               = ""
)

// Config the plugin configuration.
type Config struct {
	SanitizeExposingHeaders         bool   `json:"sanitizeExposingHeaders"`
  DefaultHeaders ConfigHeaders `json:"defaultHeaders"`
  ForceHeaders ConfigHeaders `json:"forceHeaders"`
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
  defaultHeaders := ConfigHeaders {
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

  forceHeaders := ConfigHeaders {
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
		SanitizeExposingHeaders:         true,
    DefaultHeaders: defaultHeaders,
    ForceHeaders: forceHeaders,
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
	headers := rw.Header()

	if t.Config.SanitizeExposingHeaders {
		badHeaders := badHeaders()
		for i := 0; i < len(badHeaders); i++ {
			headers.Del(badHeaders[i])
		}
	}

	contentType := headers.Get("Content-Type")

	if contentTypeIsOrStartsWith(contentType, "text/html") {
		// text/html only
		handleHeader(headers, Header_XFrameOptions, t.Config.DefaultHeaders.XFrameOptions, t.Config.ForceHeaders.XFrameOptions)
		handleHeader(headers, Header_XssProtection, t.Config.DefaultHeaders.XssProtection, t.Config.ForceHeaders.XssProtection)
	} else {
		headers.Del(Header_XFrameOptions)
		headers.Del(Header_XssProtection)
	}

	if contentTypeIsOrStartsWith(contentType, "text/html") ||
		contentTypeIsOrStartsWith(contentType, "text/xml") ||
		contentTypeIsOrStartsWith(contentType, "application/xhtml+xml") ||
		contentTypeIsOrStartsWith(contentType, "text/javascript") ||
		contentTypeIsOrStartsWith(contentType, "application/pdf") ||
		contentTypeIsOrStartsWith(contentType, "image/svg+xml") {
		handleHeader(headers, Header_ContentSecurityPolicy, t.Config.DefaultHeaders.ContentSecurityPolicy, t.Config.ForceHeaders.ContentSecurityPolicy)
		handleHeader(headers, Header_ContentSecurityPolicyReportOnly, t.Config.DefaultHeaders.ContentSecurityPolicyReportOnly, t.Config.ForceHeaders.ContentSecurityPolicyReportOnly)
	} else {
		headers.Del(Header_ContentSecurityPolicy)
		headers.Del(Header_ContentSecurityPolicyReportOnly)
	}

  handleHeader(headers, Header_ContentTypeOptions, t.Config.DefaultHeaders.ContentTypeOptions, t.Config.ForceHeaders.ContentTypeOptions)
  handleHeader(headers, Header_ReferrerPolicy, t.Config.DefaultHeaders.ReferrerPolicy, t.Config.ForceHeaders.ReferrerPolicy)
  handleHeader(headers, Header_StrictTransportSecurity, t.Config.DefaultHeaders.StrictTransportSecurity, t.Config.ForceHeaders.StrictTransportSecurity)
  handleHeader(headers, Header_CrossOriginOpenerPolicy, t.Config.DefaultHeaders.CrossOriginOpenerPolicy, t.Config.ForceHeaders.CrossOriginOpenerPolicy)
  handleHeader(headers, Header_CrossOriginEmbedderPolicy, t.Config.DefaultHeaders.CrossOriginEmbedderPolicy, t.Config.ForceHeaders.CrossOriginEmbedderPolicy)
  handleHeader(headers, Header_CrossOriginResourcePolicy, t.Config.DefaultHeaders.CrossOriginResourcePolicy, t.Config.ForceHeaders.CrossOriginResourcePolicy)
  handleHeader(headers, Header_PermissionsPolicy, t.Config.DefaultHeaders.PermissionsPolicy, t.Config.ForceHeaders.PermissionsPolicy)

	t.next.ServeHTTP(rw, req)
}

func contentTypeIsOrStartsWith(haystack string, match string) bool {
	return haystack == match || strings.HasPrefix(haystack, match+";")
}

func handleHeader(headers http.Header, headerName string, defaultValue string, forceValue string) {
	if forceValue != "" {
		headers[headerName] = []string{forceValue}
    return
  }

  if defaultValue != "" && headers.Get(headerName) == "" {
		headers[headerName]= []string{defaultValue}
	}
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
