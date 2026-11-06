"""Application exceptions, translated to HTTP responses in api.main."""

from __future__ import annotations


class AppError(Exception):
    status_code = 500
    code = "internal_error"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class NotFoundError(AppError):
    status_code = 404
    code = "not_found"

    def __init__(self, resource: str, identifier: str):
        super().__init__(f"{resource} '{identifier}' was not found")
        self.resource = resource
        self.identifier = identifier


class InvalidRequestError(AppError):
    status_code = 422
    code = "invalid_request"


class DataLoadError(AppError):
    """A data file is missing, is not valid JSON, or does not match its schema."""

    status_code = 500
    code = "data_error"
