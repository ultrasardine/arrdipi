"""Error hierarchy for the arrdipi RDP client library.

All exceptions inherit from ArrdipiError, providing a structured
error taxonomy for different failure modes in the RDP protocol stack.
"""


class ArrdipiError(Exception):
    """Base exception for all arrdipi errors."""


class ConnectionTimeoutError(ArrdipiError):
    """Raised when a TCP connection cannot be established within the timeout."""

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        super().__init__(
            f"Connection to {host}:{port} timed out after {timeout:.1f}s"
        )


class NegotiationFailureError(ArrdipiError):
    """Raised when X.224 negotiation fails with a failure code."""

    def __init__(self, failure_code: int, description: str) -> None:
        self.failure_code = failure_code
        self.description = description
        super().__init__(
            f"Negotiation failed (code 0x{failure_code:08X}): {description}"
        )


class ConnectionPhaseError(ArrdipiError):
    """Raised when a connection sequence phase fails."""

    def __init__(self, phase_number: int, phase_name: str, cause: Exception) -> None:
        self.phase_number = phase_number
        self.phase_name = phase_name
        self.cause = cause
        super().__init__(
            f"Connection failed at phase {phase_number} ({phase_name}): {cause}"
        )


class ChannelJoinError(ArrdipiError):
    """Raised when an MCS channel join request is denied."""

    def __init__(self, channel_name: str, channel_id: int) -> None:
        self.channel_name = channel_name
        self.channel_id = channel_id
        super().__init__(
            f"Failed to join channel '{channel_name}' (ID {channel_id})"
        )


class AuthenticationError(ArrdipiError):
    """Raised when NLA/CredSSP authentication fails due to invalid credentials."""

    def __init__(self, error_code: int, message: str = "") -> None:
        self.error_code = error_code
        msg = f"Authentication failed (code 0x{error_code:08X})"
        if message:
            msg += f": {message}"
        super().__init__(msg)


class NegotiationError(ArrdipiError):
    """Raised when SPNEGO/Kerberos negotiation fails."""

    def __init__(self, message: str) -> None:
        super().__init__(f"Security negotiation failed: {message}")


class PduParseError(ArrdipiError):
    """Raised when PDU parsing encounters malformed or truncated data.

    Attributes:
        pdu_type: Name of the PDU type being parsed.
        offset: Byte offset where the error occurred.
        description: Human-readable description of the error.
    """

    def __init__(self, pdu_type: str, offset: int, description: str) -> None:
        self.pdu_type = pdu_type
        self.offset = offset
        self.description = description
        super().__init__(
            f"{pdu_type} parse error at offset {offset}: {description}"
        )


class DecompressionError(ArrdipiError):
    """Raised when MPPC bulk decompression encounters corrupted data."""

    def __init__(self, message: str = "Corrupted compressed data") -> None:
        super().__init__(message)


class RleDecodeError(ArrdipiError):
    """Raised when RLE bitmap decompression fails."""

    def __init__(self, rect_index: int, byte_offset: int, message: str = "") -> None:
        self.rect_index = rect_index
        self.byte_offset = byte_offset
        msg = f"RLE decode error at rectangle {rect_index}, byte offset {byte_offset}"
        if message:
            msg += f": {message}"
        super().__init__(msg)


class FinalizationTimeoutError(ArrdipiError):
    """Raised when connection finalization PDUs are not received within timeout."""

    def __init__(self, missing_pdu: str, timeout: float) -> None:
        self.missing_pdu = missing_pdu
        self.timeout = timeout
        super().__init__(
            f"Finalization timed out waiting for {missing_pdu} after {timeout:.1f}s"
        )
