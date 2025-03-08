# src/routes/__init__.py
from .users.main import router as users_router
from .scan.main import router as scan_router
from .reports.main import router as reports_router

__all__ = ['users_router', 'scan_router', 'reports_router']