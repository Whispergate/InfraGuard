"""Ordered SQL migrations for the InfraGuard tracking DB.

Each file in this directory named ``NNNN_<slug>.sql`` is applied once,
in numeric order, and recorded in the ``schema_migrations`` table. See
``infraguard/tracking/migrator.py`` for the runner. Do not renumber or
edit an already-applied migration - add a new file instead.
"""
