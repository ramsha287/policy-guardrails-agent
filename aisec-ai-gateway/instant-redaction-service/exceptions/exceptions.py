class BaseError(Exception):
    """Base exception for all application errors."""

    def __init__(self, message: str, status_code: int = 500):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class ValidationError(BaseError):
    def __init__(self, message: str):
        super().__init__(message, status_code=400)


class InvalidRedactionTypeError(BaseError):
    def __init__(self, redaction_type: str):
        super().__init__(f"Unsupported redaction type: {redaction_type}", status_code=400)
        self.redaction_type = redaction_type


class CorruptedFileError(BaseError):
    def __init__(self):
        super().__init__("Uploaded file is corrupted or unreadable.", status_code=400)


class UnsupportedFileTypeError(BaseError):
    def __init__(self):
        super().__init__(
            "Invalid file type. Only image, text, JSON, CSV, and PDF files are supported",
            status_code=400,
        )


class ServiceUnavailableError(BaseError):
    def __init__(self, message: str = "Service unavailable"):
        super().__init__(message, status_code=503)
