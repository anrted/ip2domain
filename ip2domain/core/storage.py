"""SQLite persistence manager for scan history, results, and topology graphs.
This module re-exports StorageManager from the modular storage package for backward compatibility.
"""
from ip2domain.core.storage import StorageManager, DB_PATH

__all__ = ["StorageManager", "DB_PATH"]
