"""Sanitized errors that never include relay response bodies or credential values."""


class RelayError(Exception):
    """Base SDK error."""


class ConfigurationError(RelayError):
    """Invalid caller configuration."""


class ProtocolError(RelayError):
    """Relay response does not match the protocol."""


class InvalidEnvelope(ProtocolError):
    """An encrypted delivery failed authentication or validation."""


class TransportError(RelayError):
    """A network request could not be completed."""


class RelayHTTPError(RelayError):
    """Sanitized HTTP failure. Raw bodies are deliberately not retained."""

    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(f"Relay HTTP request failed ({status})")


class RequestExpired(RelayError):
    """The request expired before successful delivery and acknowledgment."""


class CallbackError(RelayError):
    """The local callback failed; its exception text is deliberately suppressed."""


class RelayTimeout(RelayError):
    """The caller's optional overall wait limit was reached."""


class RequestClosed(RelayError):
    """A completed or cancelled request cannot be reused."""
