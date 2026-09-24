// Dashboard entry - bundled by Vite into static/dist/dashboard-<hash>.js.
//
// This is the seed module for the incremental extraction of dashboard
// JavaScript out of the inline <script> blocks in static/index.html.
// Feature-by-feature, move logic here and delete it from the HTML.
//
// When the first feature is migrated, replace the inline <script> tags
// with one <script type="module" src="/static/dist/dashboard-<hash>.js">
// and drop `'unsafe-inline'` from the SecurityHeadersMiddleware CSP.

console.info("[infraguard] dashboard bundle loaded");
