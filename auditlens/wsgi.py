"""
WSGI entry point for running AuditLens dashboard with gunicorn.

Usage:
    gunicorn "auditlens.wsgi:create_app('/path/to/project')"

Or via environment variable:
    SCAN_PATH=/path/to/project gunicorn "auditlens.wsgi:app"
"""
from __future__ import annotations

import os


def create_app(scan_path: str | None = None):
    """Factory function for gunicorn / Azure App Service."""
    from auditlens.dashboard import _build_app

    path = scan_path or os.environ.get('SCAN_PATH', '/data/scan')
    db_path = os.environ.get('AUDITLENS_DB')
    return _build_app(path, db_path=db_path)


class _LazyApp:
    """Lazy WSGI wrapper — defers app creation until the first request.
    This avoids import-time failures when env vars are not yet set."""

    _app = None

    def _get_app(self):
        if self._app is None:
            self._app = create_app()
        return self._app

    def __call__(self, environ, start_response):
        return self._get_app()(environ, start_response)


# Module-level app for simple gunicorn invocations:
#   gunicorn auditlens.wsgi:app
app = _LazyApp()
