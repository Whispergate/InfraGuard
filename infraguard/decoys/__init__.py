"""Data-driven decoy-site generation.

Adding a new industry decoy used to mean copy-pasting an entire directory
under ``pages/`` and hand-editing ~100 lines of HTML. This module turns
that into one YAML file plus ``infraguard decoy generate --industry X``.
"""

from infraguard.decoys.generator import (
    available_industries,
    generate_blog,
    load_industry_data,
)

__all__ = ["generate_blog", "load_industry_data", "available_industries"]
