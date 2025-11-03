"""Static feature extraction routines."""

from __future__ import annotations

import re
from collections import Counter
from typing import List, Optional, Sequence
from zipfile import BadZipFile

from core.io.models import ApkScanResult
from core.io.utils import open_zip

from .dex import DexFile, DexParsingError
from .models import (
    CallGraphStats,
    ManifestFeatureSet,
    MissingValuePolicy,
    OpcodeProfile,
    StaticFeatureSet,
)

URL_PATTERN = re.compile(r"https?://[\w./?&=#%-]+", re.IGNORECASE)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_static_features(scan_result: ApkScanResult, *, opcode_ngram: int = 2) -> StaticFeatureSet:
    """Extract manifest, string and bytecode features from an APK scan result."""

    features = StaticFeatureSet(missing_policy=MissingValuePolicy.EMPTY)

    manifest_data = scan_result.extra.get("manifest")
    manifest_strings: List[str] = []
    if manifest_data is not None:
        features.manifest = ManifestFeatureSet.from_manifest(manifest_data)
        manifest_strings.extend(features.manifest.permissions)
        manifest_strings.extend(
            value
            for values in features.manifest.components.values()
            for value in values
        )
    else:
        features.missing_policy = MissingValuePolicy.NONE

    text_sources = list(manifest_strings)
    if scan_result.manifest_xml:
        text_sources.append(scan_result.manifest_xml)

    dex_strings: List[str] = []
    opcode_profile = OpcodeProfile()
    call_stats = CallGraphStats()

    dex_bytes = _read_primary_dex(scan_result)
    if dex_bytes:
        try:
            dex = DexFile(dex_bytes)
            dex_strings = dex.collect_strings()
            opcode_profile = _build_opcode_profile(dex, opcode_ngram)
            call_stats = _build_call_graph_stats(dex)
        except DexParsingError:
            features.missing_policy = MissingValuePolicy.NONE

    all_strings = text_sources + dex_strings
    features.urls = _extract_urls(all_strings)
    features.ip_addresses = _extract_ips(all_strings)
    features.opcode_profile = opcode_profile
    features.call_graph = call_stats

    return features


def _read_primary_dex(scan_result: ApkScanResult) -> Optional[bytes]:
    path = scan_result.path
    if not path.exists():
        return None
    try:
        with open_zip(path) as zf:
            try:
                with zf.open("classes.dex") as dex:
                    return dex.read()
            except KeyError:
                return None
    except (OSError, BadZipFile):
        return None


def _extract_urls(strings: Sequence[str]) -> List[str]:
    seen = set()
    urls: List[str] = []
    for value in strings:
        if not value:
            continue
        for match in URL_PATTERN.findall(value):
            normalised = match.rstrip(".,")
            if normalised not in seen:
                seen.add(normalised)
                urls.append(normalised)
    return urls


def _extract_ips(strings: Sequence[str]) -> List[str]:
    seen = set()
    ips: List[str] = []
    for value in strings:
        if not value:
            continue
        for match in IP_PATTERN.findall(value):
            if match not in seen:
                seen.add(match)
                ips.append(match)
    return ips


def _build_opcode_profile(dex: DexFile, n: int) -> OpcodeProfile:
    counter: Counter[str] = Counter()
    api_tokens: set[str] = set()

    for descriptor, code in dex.iter_methods():
        if not code or not code.opcodes:
            continue
        _accumulate_ngrams(counter, code.opcodes, n)
        called = dex.resolve_calls(code.called_methods)
        api_tokens.update(called)
    return OpcodeProfile(ngrams=dict(counter), api_tokens=sorted(api_tokens))


def _accumulate_ngrams(counter: Counter[str], sequence: Sequence[int], n: int) -> None:
    if n <= 0:
        return
    if len(sequence) < n:
        return
    for idx in range(len(sequence) - n + 1):
        ngram = sequence[idx : idx + n]
        key = "-".join(f"{opcode:02x}" for opcode in ngram)
        counter[key] += 1


def _build_call_graph_stats(dex: DexFile) -> CallGraphStats:
    edges = set()
    out_degree = Counter()
    in_degree = Counter()
    nodes = set()

    for descriptor, code in dex.iter_methods():
        node = descriptor.fqname
        nodes.add(node)
        if code is None:
            continue
        targets = dex.resolve_calls(code.called_methods)
        for target in targets:
            nodes.add(target)
            edge = (node, target)
            if edge not in edges:
                edges.add(edge)
                out_degree[node] += 1
                in_degree[target] += 1

    node_count = len(nodes)
    edge_count = len(edges)
    avg_out_degree = (sum(out_degree.values()) / node_count) if node_count else 0.0
    max_out = max(out_degree.values()) if out_degree else 0
    max_in = max(in_degree.values()) if in_degree else 0

    return CallGraphStats(
        node_count=node_count,
        edge_count=edge_count,
        avg_out_degree=avg_out_degree,
        max_out_degree=max_out,
        max_in_degree=max_in,
    )
