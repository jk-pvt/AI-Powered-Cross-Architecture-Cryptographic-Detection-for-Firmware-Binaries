"""Typed exception hierarchy for OpenCryptoDetect."""



class OCDError(Exception):
    """Base exception for all OpenCryptoDetect errors."""

    def __init__(self, message: str, code: str | None = None, details: str | None = None):
        super().__init__(message)
        self.message = message
        self.code = code or "ERR-000"
        self.details = details

    def __str__(self) -> str:
        if self.details:
            return f"ERROR [{self.code}]: {self.message}\nDetails: {self.details}"
        return f"ERROR [{self.code}]: {self.message}"


class InputInspectionError(OCDError):
    """Raised when file inspection fails or input is malformed."""

    def __init__(self, message: str, details: str | None = None):
        super().__init__(message, code="INSPECT-001", details=details)


class UnsupportedFormatError(OCDError):
    """Raised when binary format is unsupported."""

    def __init__(self, message: str, details: str | None = None):
        super().__init__(message, code="FMT-001", details=details)


class ArchitectureDetectionError(OCDError):
    """Raised when architecture cannot be determined."""

    def __init__(self, message: str = "Unable to determine architecture.", details: str | None = None):
        super().__init__(message, code="ARCH-001", details=details)


class BinaryAnalysisError(OCDError):
    """Raised when disassembly or CFG analysis fails."""

    def __init__(self, message: str, details: str | None = None):
        super().__init__(message, code="ANALYSIS-001", details=details)


class FirmwareExtractionError(OCDError):
    """Raised when firmware unpacking fails or security limits are exceeded."""

    def __init__(self, message: str, details: str | None = None):
        super().__init__(message, code="EXTRACT-001", details=details)


class SecurityViolationError(OCDError):
    """Raised when safety checks detect malicious content like directory traversal."""

    def __init__(self, message: str, details: str | None = None):
        super().__init__(message, code="SEC-001", details=details)


class MLModelError(OCDError):
    """Raised when ML model loading or inference fails."""

    def __init__(self, message: str, details: str | None = None):
        super().__init__(message, code="ML-001", details=details)


class CBOMGenerationError(OCDError):
    """Raised when CBOM generation or validation fails."""

    def __init__(self, message: str, details: str | None = None):
        super().__init__(message, code="CBOM-001", details=details)
