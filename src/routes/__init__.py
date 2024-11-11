# src/routes/__init__.py
from .users.main import router as users_router

__all__ = ['users_router']