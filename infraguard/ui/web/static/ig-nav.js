/* Shared dashboard chrome: theme persistence and the nav.
 *
 * This lived only in index.html, so the preference was written on the
 * Overview page and then ignored everywhere else: the other pages never read
 * localStorage, never set data-theme, and had no toggle of their own. Picking
 * light mode and then clicking through to Decoys put you back in the dark.
 *
 * Loaded from <head> rather than deferred, so data-theme is on <html> before
 * the first paint. Deferring it would show a dark flash on every navigation
 * for anyone using the light theme.
 */
(function () {
    "use strict";

    var KEY = "infraguard-theme";

    // localStorage throws in a few situations (private windows, blocked site
    // data). A themed dashboard is not worth a broken page, so fall back to
    // the default rather than letting it propagate.
    function stored() {
        try {
            return localStorage.getItem(KEY) || "dark";
        } catch (e) {
            return "dark";
        }
    }

    function apply(theme) {
        document.documentElement.setAttribute("data-theme", theme);
        var btn = document.getElementById("theme-toggle");
        if (btn) {
            btn.textContent = theme === "light" ? "☀ Dark" : "☾ Light";
        }
    }

    // Global: index.html wires its existing button with onclick="toggleTheme()".
    window.toggleTheme = function () {
        var next =
            document.documentElement.getAttribute("data-theme") === "light"
                ? "dark"
                : "light";
        try {
            localStorage.setItem(KEY, next);
        } catch (e) {
            /* preference will not persist, but the page still switches */
        }
        apply(next);
    };

    apply(stored());

    document.addEventListener("DOMContentLoaded", function () {
        // Give every page a toggle. index.html ships its own button inside
        // .ig-actions; the rest get one built here so the control is not
        // missing on three pages out of four.
        if (!document.getElementById("theme-toggle")) {
            var host =
                document.querySelector(".ig-actions") ||
                document.querySelector(".header-right");
            if (host) {
                var btn = document.createElement("button");
                btn.id = "theme-toggle";
                btn.type = "button";
                btn.className = host.classList.contains("ig-actions")
                    ? "ig-btn-ghost"
                    : "btn btn-ghost";
                btn.title = "Toggle theme";
                btn.addEventListener("click", window.toggleTheme);
                host.insertBefore(btn, host.firstChild);
            }
        }
        apply(document.documentElement.getAttribute("data-theme") || stored());
    });
})();
