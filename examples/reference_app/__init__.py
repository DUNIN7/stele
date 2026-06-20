"""Stele reference host — a minimal standalone FastAPI app that mounts
``stele.router`` and composes signup + login over Stele's primitives.

Built for Phase 7 P7-3 (CR-2026-116). It is the clone-and-run-and-*use* proof:
a stranger stands up Postgres, runs Stele's baseline migration, fills a generated
``.env``, starts this app, and registers a real passkey in a browser that
round-trips through ``stele.router``.

This is host code, not part of the ``stele`` package. It demonstrates the
authorization boundary in practice — Stele *authenticates* (the mounted router +
the primitives this app composes); the host *authorizes* and owns the marquee
flows (signup/login orchestration lives here, B-first).
"""
