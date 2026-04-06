"""Canary token injection for decoy pages.

Injects invisible tracking elements into HTML decoy responses that
phone home when a blue teamer interacts with the decoy site. This
generates intelligence about who is investigating the redirector.

Supported canary types:
  - Tracking pixel: 1x1 transparent image that triggers a callback
  - Honeypot link: Hidden link that crawlers/scanners follow
  - Hidden form: Fake login form that captures credential submission

All canary callbacks hit InfraGuard's own API so the operator is
alerted via the normal plugin pipeline (Discord, Slack, SIEM, etc.).
"""

from __future__ import annotations

import hashlib
import time


def generate_canary_id() -> str:
    """Generate a unique canary token ID."""
    raw = f"canary-{time.time_ns()}".encode()
    return hashlib.sha256(raw).hexdigest()[:12]


def inject_tracking_pixel(html: str, callback_path: str = "/_ig/px") -> str:
    """Inject a 1x1 tracking pixel before </body>.

    The pixel URL includes a unique canary ID so each page render
    generates a distinct callback.
    """
    canary_id = generate_canary_id()
    pixel = (
        f'<img src="{callback_path}?c={canary_id}" '
        f'width="1" height="1" alt="" '
        f'style="position:absolute;left:-9999px" />'
    )
    if "</body>" in html:
        return html.replace("</body>", f"{pixel}\n</body>", 1)
    # No closing body tag — append
    return html + pixel


def inject_honeypot_link(
    html: str,
    callback_path: str = "/_ig/hp",
    link_text: str = "",
) -> str:
    """Inject a hidden honeypot link that only crawlers/scanners follow.

    The link is invisible to normal users (display:none) but automated
    tools that parse HTML will follow it, revealing themselves.
    """
    canary_id = generate_canary_id()
    # Hidden via CSS — browsers won't render it, but HTML parsers see it
    link = (
        f'<a href="{callback_path}?c={canary_id}" '
        f'style="display:none;visibility:hidden;position:absolute;left:-9999px" '
        f'tabindex="-1" aria-hidden="true">{link_text}</a>'
    )
    if "</body>" in html:
        return html.replace("</body>", f"{link}\n</body>", 1)
    return html + link


def inject_honeypot_form(
    html: str,
    callback_path: str = "/_ig/hf",
) -> str:
    """Inject a hidden fake login form that captures credential submissions.

    The form is invisible to real users but automated credential
    stuffing tools and manual investigators may interact with it.
    """
    canary_id = generate_canary_id()
    form = (
        f'<form action="{callback_path}?c={canary_id}" method="POST" '
        f'style="position:absolute;left:-9999px;opacity:0;height:0;overflow:hidden" '
        f'tabindex="-1" aria-hidden="true">'
        f'<input type="text" name="username" autocomplete="username" />'
        f'<input type="password" name="password" autocomplete="current-password" />'
        f'<button type="submit">Login</button>'
        f'</form>'
    )
    if "</body>" in html:
        return html.replace("</body>", f"{form}\n</body>", 1)
    return html + form


def inject_all_canaries(
    html: str,
    enable_pixel: bool = True,
    enable_honeypot_link: bool = True,
    enable_honeypot_form: bool = False,
) -> str:
    """Inject all enabled canary types into an HTML response."""
    if enable_pixel:
        html = inject_tracking_pixel(html)
    if enable_honeypot_link:
        html = inject_honeypot_link(html)
    if enable_honeypot_form:
        html = inject_honeypot_form(html)
    return html
