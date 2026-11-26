from __future__ import annotations


class SigForgeError(Exception):
    """Base exception for all sigforge errors."""


class BinaryFormatError(SigForgeError):
    """Raised when input bytes are not a valid x86-64 PE32+ or ELF64 image."""


class RvaOutOfBoundsError(SigForgeError):
    """Raised when a target RVA/VA does not map into an executable section."""


class DecodeError(SigForgeError):
    """Raised when instruction decoding fails at the target anchor."""


class AnchorNotFoundError(SigForgeError):
    """Raised when multi-build anchoring cannot confidently locate target in v2."""


class SynthesisError(SigForgeError):
    """Raised when no unique signature can be synthesized within constraints."""


class SpecValidationError(SigForgeError):
    """Raised when a SigSpec or pattern string is malformed."""
