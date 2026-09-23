class BaseError(Exception):
    """Base exception for all application errors."""

    def __init__(self, message: str, status_code: int = 500):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class ProjectNotFoundError(BaseError):
    def __init__(self, project_id: str):
        super().__init__(f"Project with ID {project_id} not found", status_code=404)


class ProjectAlreadyExistsError(BaseError):
    def __init__(self, project_name: str):
        super().__init__(
            f"Project with name '{project_name}' already exists", status_code=400
        )


class ApiKeyNotFoundError(BaseError):
    def __init__(self, key_id: str):
        super().__init__(f"API key with ID {key_id} not found", status_code=404)


class ValidationError(BaseError):
    def __init__(self, message: str):
        super().__init__(message, status_code=400)


class ServiceUnavailableError(BaseError):
    def __init__(self, message: str = "Service unavailable"):
        super().__init__(message, status_code=503)
