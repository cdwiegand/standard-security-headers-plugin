# Security Headers Plugin

This plugin will append some standard security headers based on the response mime-type.

## Configuration example:

```
http:
  middlewares:
    standard-security-headers:
      plugin:
        standard-security-headers:
          sanitizeExposingHeaders: "true"
          defaultHeaders:
            xframeOptions: "SAMEORIGIN"
          forceHeaders:
            contentTypeOptions: "nosniff"
```

## Testing Methods

Testing by using local plugin functionality, assuming the code is checked out to `C:\devel\standard-security-headers-plugin`:

```bash
docker run --rm -it -p 8888:80 -v C:\devel\standard-security-headers-plugin\:/srv/plugins-local/src/github.com/cdwiegand/standard-security-headers-plugin:ro -w /srv traefik:3.0 --entryPoints.web.address=:80 --experimental.localPlugins.standard_security_headers.modulename=github.com/cdwiegand/standard-security-headers-plugin --providers.file.filename=/srv/plugins-local/src/github.com/cdwiegand/standard-security-headers-plugin/testing.traefik.yml --api=true --api.dashboard=true
```

and go to <http://localhost:8888/dashboard/> and inspect the browser's Network tab to see the Server header in the response replaced with "Nope/2.0".
