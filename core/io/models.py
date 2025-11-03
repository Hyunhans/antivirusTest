"""Data models for APK scanning."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class ScanErrorCode(str, Enum):
    """Standardised reason codes for APK scan failures."""

    FILE_NOT_FOUND = "file_not_found"
    IO_ERROR = "io_error"
    ZIP_ERROR = "zip_error"
    MANIFEST_PARSE_ERROR = "manifest_parse_error"
    SIGNATURE_PARSE_ERROR = "signature_parse_error"
    DEX_PARSE_ERROR = "dex_parse_error"
    UNSUPPORTED_FORMAT = "unsupported_format"
    UNKNOWN = "unknown"


@dataclass
class ScanError:
    """Structured representation of an error encountered during scanning."""

    code: ScanErrorCode
    message: str
    detail: Optional[str] = None


@dataclass
class SignatureInfo:
    """Signature related information extracted from an APK."""

    v1: List[str] = field(default_factory=list)
    v2: bool = False


@dataclass
class ApkScanResult:
    """Metadata extracted from a single APK file."""

    path: Path
    sha256: Optional[str] = None
    package_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    manifest_xml: Optional[str] = None
    signatures: SignatureInfo = field(default_factory=SignatureInfo)
    cache_hit: bool = False
    errors: List[ScanError] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def add_error(self, code: ScanErrorCode, message: str, detail: Optional[str] = None) -> None:
        """Append a new error to the scan result."""

        self.errors.append(ScanError(code=code, message=message, detail=detail))

    @property
    def ok(self) -> bool:
        """Return whether the scan completed without fatal errors."""

        return not self.errors
