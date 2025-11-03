"""Data schemas for static feature extraction."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from core.io.manifest import IntentFilter, ManifestData


class MissingValuePolicy(str, Enum):
    """Policy describing how missing features are represented."""

    EMPTY = "empty"
    ZERO = "zero"
    NONE = "none"


@dataclass
class IntentFilterFeature:
    component: str
    actions: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    data_schemes: List[str] = field(default_factory=list)

    @classmethod
    def from_manifest(cls, intent: IntentFilter) -> "IntentFilterFeature":
        return cls(
            component=intent.component,
            actions=list(intent.actions),
            categories=list(intent.categories),
            data_schemes=list(intent.data_schemes),
        )


@dataclass
class ManifestFeatureSet:
    package_name: Optional[str] = None
    version_code: Optional[str] = None
    version_name: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    components: Dict[str, List[str]] = field(default_factory=dict)
    intent_filters: List[IntentFilterFeature] = field(default_factory=list)

    @classmethod
    def from_manifest(cls, manifest: ManifestData) -> "ManifestFeatureSet":
        return cls(
            package_name=manifest.package_name,
            version_code=manifest.version_code,
            version_name=manifest.version_name,
            permissions=list(manifest.permissions),
            components={key: list(values) for key, values in manifest.components.items()},
            intent_filters=[IntentFilterFeature.from_manifest(item) for item in manifest.intent_filters],
        )


@dataclass
class OpcodeProfile:
    ngrams: Dict[str, int] = field(default_factory=dict)
    api_tokens: List[str] = field(default_factory=list)


@dataclass
class CallGraphStats:
    node_count: int = 0
    edge_count: int = 0
    avg_out_degree: float = 0.0
    max_out_degree: int = 0
    max_in_degree: int = 0


@dataclass
class StaticFeatureSet:
    """Container for static features extracted from an APK."""

    manifest: ManifestFeatureSet = field(default_factory=ManifestFeatureSet)
    urls: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    opcode_profile: OpcodeProfile = field(default_factory=OpcodeProfile)
    call_graph: CallGraphStats = field(default_factory=CallGraphStats)
    missing_policy: MissingValuePolicy = MissingValuePolicy.EMPTY
