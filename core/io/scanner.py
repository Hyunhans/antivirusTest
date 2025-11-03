"""High-level scanning routines for APK files."""

from __future__ import annotations

import concurrent.futures
import logging
from pathlib import Path
from typing import List, Optional
from zipfile import BadZipFile

from .manifest import decode_manifest
from .models import ApkScanResult, ScanErrorCode, SignatureInfo
from .utils import HashCache, compute_sha256, detect_v2_signature, iter_apk_files, open_zip

logger = logging.getLogger(__name__)


def scan_apk(path: Path | str, *, precomputed_hash: Optional[str] = None) -> ApkScanResult:
    """Scan a single APK file and extract metadata."""

    apk_path = Path(path)
    result = ApkScanResult(path=apk_path)

    if not apk_path.exists():
        result.add_error(ScanErrorCode.FILE_NOT_FOUND, "APK file does not exist")
        return result

    try:
        sha256 = precomputed_hash or compute_sha256(apk_path)
        result.sha256 = sha256
    except OSError as exc:
        result.add_error(ScanErrorCode.IO_ERROR, "Failed to compute SHA-256", str(exc))
        return result

    try:
        with open_zip(apk_path) as zf:
            manifest_bytes = _read_manifest(zf)
            if manifest_bytes is not None:
                try:
                    manifest_xml, manifest_data = decode_manifest(manifest_bytes)
                    result.manifest_xml = manifest_xml
                    result.package_name = manifest_data.package_name
                    result.version_code = manifest_data.version_code
                    result.version_name = manifest_data.version_name
                    result.extra["manifest"] = manifest_data
                except Exception as exc:  # pragma: no cover - best effort fallback
                    result.add_error(
                        ScanErrorCode.MANIFEST_PARSE_ERROR,
                        "Failed to decode AndroidManifest.xml",
                        str(exc),
                    )
            else:
                result.add_error(
                    ScanErrorCode.MANIFEST_PARSE_ERROR,
                    "AndroidManifest.xml missing from archive",
                )

            signatures = _extract_signatures(apk_path, zf)
            result.signatures = signatures
    except BadZipFile as exc:
        result.add_error(ScanErrorCode.ZIP_ERROR, "APK archive appears to be corrupt", str(exc))
    except OSError as exc:
        result.add_error(ScanErrorCode.IO_ERROR, "Failed to open APK archive", str(exc))
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Unexpected error while scanning APK %s", apk_path)
        result.add_error(ScanErrorCode.UNKNOWN, "Unexpected error during scanning", str(exc))

    return result


def _read_manifest(zf) -> Optional[bytes]:
    for name in ("AndroidManifest.xml", "androidmanifest.xml"):
        try:
            with zf.open(name) as manifest:
                return manifest.read()
        except KeyError:
            continue
    return None


def _extract_signatures(path: Path, zf) -> SignatureInfo:
    signatures = SignatureInfo()
    try:
        signatures.v1 = [info.filename for info in zf.infolist() if info.filename.upper().startswith("META-INF/")]
        signatures.v1 = [name for name in signatures.v1 if name.upper().endswith((".RSA", ".DSA", ".EC"))]
        signatures.v2 = detect_v2_signature(path)
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Failed to extract signature information from %s", path)
        raise
    return signatures


def scan_dir(directory: Path | str, *, workers: int = 4) -> List[ApkScanResult]:
    """Scan all APK files under ``directory`` using a pool of workers."""

    root = Path(directory)
    files = list(iter_apk_files(root))
    if not files:
        return []

    cache = HashCache()
    results: List[ApkScanResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(4, workers)) as executor:
        future_to_path = {}
        for apk_path in files:
            try:
                sha256 = compute_sha256(apk_path)
            except OSError as exc:
                result = ApkScanResult(path=apk_path)
                result.add_error(ScanErrorCode.IO_ERROR, "Failed to compute SHA-256", str(exc))
                results.append(result)
                continue

            if cache.check_and_add(sha256):
                skipped = ApkScanResult(path=apk_path, sha256=sha256, cache_hit=True)
                results.append(skipped)
                continue

            future = executor.submit(scan_apk, apk_path, precomputed_hash=sha256)
            future_to_path[future] = apk_path

        for future in concurrent.futures.as_completed(future_to_path):
            try:
                result = future.result()
            except Exception as exc:  # pragma: no cover
                apk_path = future_to_path[future]
                failure = ApkScanResult(path=apk_path)
                failure.add_error(ScanErrorCode.UNKNOWN, "Worker failed to scan APK", str(exc))
                results.append(failure)
                continue
            results.append(result)

    return results
