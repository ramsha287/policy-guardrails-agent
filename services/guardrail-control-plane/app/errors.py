from __future__ import annotations


class NotFound(Exception):
    pass


class ValidationFailed(Exception):
    def __init__(self, message: str, errors: list[str] | None = None, warnings: list[str] | None = None) -> None:
        super().__init__(message)
        self.errors = errors or []
        self.warnings = warnings or []


class StateConflict(Exception):
    """The request conflicts with current state (e.g. approving your own publish request)."""
