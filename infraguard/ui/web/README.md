# InfraGuard dashboard UI

This directory holds the InfraGuard dashboard's browser code.

## Layout

    infraguard/ui/web/
    ├── package.json      # npm workspace
    ├── vite.config.js    # Vite bundler config
    ├── src/              # ES module source (bundled)
    │   ├── dashboard.js
    │   └── decoys.js
    └── static/           # served by Starlette at /static
        ├── index.html    # legacy single-file page (kept as fallback)
        ├── decoys.html   # legacy single-file page (kept as fallback)
        ├── health.html
        ├── infraguard_icon.svg
        └── dist/         # Vite output (generated; git-ignored)

## Building

    cd infraguard/ui/web
    npm install
    npm run build

That writes hashed bundles to `static/dist/` alongside a `manifest.json`
the Python side can read to resolve logical entries → hashed filenames.

## Airgapped / no-build mode

If `static/dist/` is absent, the Starlette route falls back to serving
`static/index.html` and `static/decoys.html` directly. Existing operators
who deploy from a tarball keep working unchanged.

## Why the split

The pre-v0.5 dashboard shipped `index.html` (868 LOC) and `decoys.html`
(1235 LOC) with all JS and CSS inline. That meant:

* the `Content-Security-Policy` header had to allow `'unsafe-inline'`;
* code review of any UI change was a diff over an enormous single file;
* there was no way to tree-shake, minify, cache-bust, or hot-reload.

The Vite bundler on this side and the `SecurityHeadersMiddleware` on the
Python side are the two pieces needed to eventually drop `'unsafe-inline'`
from the CSP. Migrate one feature at a time: move a component's JS
into `src/`, import it from a `<script type="module" src="...">` tag,
and delete the inline block from the HTML file.

## Serving the built assets

`create_api_app` in `infraguard/ui/api/app.py` already mounts
`ui/web/static` at `/static`. Once `static/dist/` exists after a build,
its files are reachable at `/static/dist/*` with no code change here -
just update `index.html` / `decoys.html` to reference the hashed names
from the generated `manifest.json`.
