class AuthTokenError(Exception):
    """
        Base exception used for all auth token errors.
    """
    pass


class ConfigError(AuthTokenError):
    """
        Raised when an error occurs with a configuration parameter.
    """
    pass


class InvalidValueError(AuthTokenError):
    """
        Raised when metadata used to create or verify a token is invalid.
    """
    pass


class InvalidTokenError(AuthTokenError):
    """
        Parent class for all errors that can occur when validating a token.
    """
    pass


class TokenExpiredError(InvalidTokenError):
    """
        Raised when a token has expired.
    """
    pass


class TokenSignatureError(InvalidTokenError):
    """
        Raised when a token has an invalid signature.
    """
    pass
