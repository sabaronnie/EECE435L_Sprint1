class ApiError(Exception):
    def __init__(self, message, code=400, details=None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details
