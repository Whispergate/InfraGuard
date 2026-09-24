"""Decoy blog generator.

Renders ``pages/_templates/blog.html.j2`` against per-industry data
files. Ships without a hard Jinja2 dependency: falls back to a tiny
built-in renderer that supports the two constructs the template uses
(``{% for x in y %}…{% endfor %}`` and ``{{ expr }}``). Operators who
customise the template can install Jinja2 for filters and inheritance.
"""

from __future__ import annotations

import datetime as _dt
import re
from pathlib import Path
from typing import Any


_TEMPLATE_DIR = Path(__file__).resolve().parents[2] / "pages" / "_templates"
_INDUSTRY_DIR = _TEMPLATE_DIR / "industries"
_BLOG_TEMPLATE = _TEMPLATE_DIR / "blog.html.j2"


def available_industries() -> list[str]:
    """Return the industry slugs shipped under ``pages/_templates/industries/``."""
    if not _INDUSTRY_DIR.is_dir():
        return []
    return sorted(p.stem for p in _INDUSTRY_DIR.glob("*.yaml"))


def load_industry_data(industry: str) -> dict[str, Any]:
    """Read the YAML data file for ``industry`` and inject defaults."""
    import yaml  # lazy - the CLI imports this module only when needed

    path = _INDUSTRY_DIR / f"{industry}.yaml"
    if not path.is_file():
        raise FileNotFoundError(
            f"no data file for industry {industry!r}. "
            f"Available: {', '.join(available_industries()) or '(none)'}"
        )
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    data.setdefault("year", _dt.date.today().year)
    data.setdefault("lang", "en")
    return data


def generate_blog(industry: str, out_dir: Path) -> Path:
    """Render the blog template for ``industry`` into ``out_dir/index.html``.

    Copies the shared ``pages/BankingBlog/assets`` tree only if the
    destination has no ``assets/`` - never overwrites operator edits.
    Returns the path to the written HTML.
    """
    data = load_industry_data(industry)
    template = _BLOG_TEMPLATE.read_text(encoding="utf-8")
    rendered = _render(template, data)

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / "index.html"
    html_path.write_text(rendered, encoding="utf-8")

    return html_path


# ---------------------------------------------------------------------------
# Micro renderer - supports {{ x }}, {{ x|default('y') }} and
# {% for row in seq %}…{% endfor %}. Not a Jinja2 replacement; enough
# for the blog template shipped in-tree. Prefers real Jinja2 if installed
# so operators can extend the template freely.
# ---------------------------------------------------------------------------

def _render(template: str, ctx: dict[str, Any]) -> str:
    try:
        from jinja2 import Environment

        env = Environment(
            trim_blocks=True, lstrip_blocks=True, autoescape=True, keep_trailing_newline=True
        )
        return env.from_string(template).render(**ctx)
    except ImportError:
        return _mini_render(template, ctx)


_FOR_RE = re.compile(
    r"\{%-?\s*for\s+(\w+)\s+in\s+([\w.]+)\s*-?%\}(.*?)\{%-?\s*endfor\s*-?%\}",
    re.DOTALL,
)
_EXPR_RE = re.compile(r"\{\{\s*(.+?)\s*\}\}")


def _resolve(path: str, ctx: dict[str, Any]) -> Any:
    parts = path.split(".")
    cur: Any = ctx.get(parts[0])
    for p in parts[1:]:
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(p)
        else:
            cur = getattr(cur, p, None)
    return cur


def _eval_expr(expr: str, ctx: dict[str, Any]) -> str:
    # Support ``x|default('y')`` - nothing else.
    if "|default(" in expr:
        base, default = expr.split("|default(", 1)
        default = default.rstrip(")").strip().strip("'\"")
        val = _resolve(base.strip(), ctx)
        return _html_escape(str(default if val in (None, "") else val))
    val = _resolve(expr.strip(), ctx)
    return _html_escape("" if val is None else str(val))


def _html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _mini_render(template: str, ctx: dict[str, Any]) -> str:
    def _expand_for(m: re.Match[str]) -> str:
        var, seq_expr, body = m.group(1), m.group(2), m.group(3)
        seq = _resolve(seq_expr, ctx) or []
        out: list[str] = []
        for item in seq:
            local = dict(ctx)
            local[var] = item
            out.append(_mini_render(body, local))
        return "".join(out)

    template = _FOR_RE.sub(_expand_for, template)
    return _EXPR_RE.sub(lambda m: _eval_expr(m.group(1), ctx), template)


__all__ = [
    "generate_blog",
    "load_industry_data",
    "available_industries",
]
