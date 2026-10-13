"""Persistent event and dead-letter storage."""
from siftlog.store.sqlite import SCHEMA_VERSION, EventStore, StoreError

__all__ = ["SCHEMA_VERSION", "EventStore", "StoreError"]
