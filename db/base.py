"""Declarative base for NekoWatch ORM models."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared metadata registry for every NekoWatch ORM model."""
