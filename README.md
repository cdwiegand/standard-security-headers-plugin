# Security Headers Plugin

This Traefik middleware adds standard security headers to every response, and (optionally) removes headers that expose details about the backend's software, such as `Server` and `X-Powered-By`.

Headers are applied after the backend responds, so the plugin can see what the backend already set.

## How headers are applied

Each header can be configured in two places:

- `defaultHeaders`: used only when the backend did not set the header itself. A value from the backend passes through untouched.
- `forceHeaders`: always written, replacing whatever the backend sent.

A force value takes precedence over a default value. An empty value means "not configured".

### Disabling a header with `-`

Set a header to `-` to turn it off:

- In `forceHeaders`, `-` always **removes** the header from the response, even when the backend set it.
- In `defaultHeaders`, `-` means **no default is added**. If the backend sets the header, its value still passes through.

## Configuration example

```yaml
http:
  middlewares:
    standard-security-headers:
      plugin:
        standard_security_headers:
          sanitizeExposingHeaders: true
          defaultHeaders:
            xframeOptions: "DENY"
            strictTransportSecurity: "-"   # don't add HSTS unless the backend does
          forceHeaders:
            contentTypeOptions: "nosniff"
            permissionsPolicy: "-"         # always strip Permissions-Policy
```

## Options

| Option | Header | Default | Force |
| --- | --- | --- | --- |
| `xframeOptions` | `X-Frame-Options` | `SAMEORIGIN` | |
| `contentTypeOptions` | `X-Content-Type-Options` | `nosniff` | `nosniff` |
| `xssProtection` | `X-XSS-Protection` | `1` | `1` |
| `referrerPolicy` | `Referrer-Policy` | `strict-origin-when-cross-origin` | |
| `strictTransportSecurity` | `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` | |
| `contentSecurityPolicy` | `Content-Security-Policy` | | |
| `contentSecurityPolicyReportOnly` | `Content-Security-Policy-Report-Only` | | |
| `crossOriginOpenerPolicy` | `Cross-Origin-Opener-Policy` | | |
| `crossOriginEmbedderPolicy` | `Cross-Origin-Embedder-Policy` | | |
| `crossOriginResourcePolicy` | `Cross-Origin-Resource-Policy` | | |
| `permissionsPolicy` | `Permissions-Policy` | | |

`sanitizeExposingHeaders` defaults to `true`. It removes the headers on the [OWASP Secure Headers removal list](https://owasp.org/www-project-secure-headers/ci/headers_remove.json), plus `X-Runtime` and `X-Version`.

The HSTS default does not include `preload`. Add it yourself (for example `forceHeaders.strictTransportSecurity: "max-age=63072000; includeSubDomains; preload"`) only once every subdomain serves HTTPS, because removing a domain from browser preload lists is slow.

## Testing Methods

Run the unit tests:

```bash
go test ./...
```

Testing by using local plugin functionality, assuming the code is checked out to `C:\devel\standard-security-headers-plugin`:

```bash
docker run --rm -it -p 8888:80 -v C:\devel\standard-security-headers-plugin\:/srv/plugins-local/src/github.com/cdwiegand/standard-security-headers-plugin:ro -w /srv traefik:3.0 --entryPoints.web.address=:80 --experimental.localPlugins.standard_security_headers.modulename=github.com/cdwiegand/standard-security-headers-plugin --providers.file.filename=/srv/plugins-local/src/github.com/cdwiegand/standard-security-headers-plugin/testing.traefik.yml --api=true --api.dashboard=true
```

and go to <http://localhost:8888/dashboard/> and inspect the browser's Network tab to see the security headers on the response.
