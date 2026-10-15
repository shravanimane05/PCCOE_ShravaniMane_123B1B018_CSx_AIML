"""Architecture Analyzer for AutoTARA AI.

Parses architecture baseline definitions, inspects components, interfaces,
data flows, and trust boundaries, and derives attack surfaces and retrieval contexts.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from autotara.data_loader import DataLoader


@dataclass
class AttackSurfaceContext:
    """Context derived from an asset, interface, and boundary crossing for threat analysis."""
    asset_id: str
    asset_name: str
    asset_type: str
    asset_category: str
    hosted_components: List[str]
    interface_ids: List[str]
    protocols: List[str]
    trust_boundary_ids: List[str]
    description: str

    def build_query(self) -> str:
        """Build retrieval query string from asset name/type, protocols, and boundary context.

        Rule 1: Never include the pattern 'keywords' field in a query.
        """
        parts = [
            f"Asset: {self.asset_name}",
            f"Type: {self.asset_type}",
            f"Category: {self.asset_category}",
        ]
        if self.protocols:
            parts.append(f"Protocols: {', '.join(self.protocols)}")
        if self.trust_boundary_ids:
            parts.append(f"Trust Boundaries: {', '.join(self.trust_boundary_ids)}")
        if self.description:
            parts.append(f"Description: {self.description}")
        return " | ".join(parts)


class ArchitectureAnalyzer:
    """Analyzes vehicle system architecture topology and derives threat modeling contexts."""

    def __init__(self, architecture_data: Dict[str, Any]):
        self.raw = architecture_data
        self.version = self.raw.get("version", "1.0")
        self.name = self.raw.get("name", "")
        self.description = self.raw.get("description", "")

        self.components: Dict[str, Dict[str, Any]] = {
            c["id"]: c for c in self.raw.get("components", [])
        }
        self.interfaces: Dict[str, Dict[str, Any]] = {
            i["id"]: i for i in self.raw.get("interfaces", [])
        }
        self.data_flows: Dict[str, Dict[str, Any]] = {
            df["id"]: df for df in self.raw.get("data_flows", [])
        }
        self.trust_zones: Dict[str, Dict[str, Any]] = {
            tz["id"]: tz for tz in self.raw.get("trust_zones", [])
        }
        self.trust_boundaries: Dict[str, Dict[str, Any]] = {
            tb["id"]: tb for tb in self.raw.get("trust_boundaries", [])
        }
        self.assets: Dict[str, Dict[str, Any]] = {
            a["id"]: a for a in self.raw.get("assets", [])
        }

    @classmethod
    def from_loader(cls, loader: Optional[DataLoader] = None, version: str = "v1") -> "ArchitectureAnalyzer":
        dl = loader or DataLoader()
        return cls(dl.load_architecture(version))

    def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        return self.assets.get(asset_id)

    def get_component(self, component_id: str) -> Optional[Dict[str, Any]]:
        return self.components.get(component_id)

    def get_interface(self, interface_id: str) -> Optional[Dict[str, Any]]:
        return self.interfaces.get(interface_id)

    def get_interfaces_for_component(self, component_id: str) -> List[Dict[str, Any]]:
        """Return all interfaces connected to a given component as source or target."""
        results = []
        for iface in self.interfaces.values():
            if iface.get("source_component_id") == component_id or iface.get("target_component_id") == component_id:
                results.append(iface)
        return results

    def get_trust_boundaries_for_component(self, component_id: str) -> List[str]:
        """Return IDs of all trust boundaries crossed by interfaces connected to the component."""
        tb_ids: Set[str] = set()
        for iface in self.get_interfaces_for_component(component_id):
            tb_id = iface.get("trust_boundary_id")
            if tb_id:
                tb_ids.add(tb_id)
        return sorted(list(tb_ids))

    def derive_attack_surface(self, asset_id: str) -> AttackSurfaceContext:
        """Derive complete attack surface context for a specific asset."""
        asset = self.assets.get(asset_id)
        if not asset:
            raise KeyError(f"Asset '{asset_id}' not found in architecture.")

        hosted_comps = asset.get("hosted_on", [])
        connected_ifaces: Dict[str, Dict[str, Any]] = {}
        for comp_id in hosted_comps:
            for iface in self.get_interfaces_for_component(comp_id):
                connected_ifaces[iface["id"]] = iface

        protocols: Set[str] = set()
        tb_ids: Set[str] = set()

        for iface in connected_ifaces.values():
            proto = iface.get("protocol")
            if proto:
                protocols.add(proto)
            tb = iface.get("trust_boundary_id")
            if tb:
                tb_ids.add(tb)

        return AttackSurfaceContext(
            asset_id=asset_id,
            asset_name=asset.get("name", ""),
            asset_type=asset.get("type", ""),
            asset_category=asset.get("category", ""),
            hosted_components=hosted_comps,
            interface_ids=sorted(list(connected_ifaces.keys())),
            protocols=sorted(list(protocols)),
            trust_boundary_ids=sorted(list(tb_ids)),
            description=asset.get("description", ""),
        )

    def derive_all_attack_surfaces(self) -> Dict[str, AttackSurfaceContext]:
        """Derive attack surfaces for all assets in the architecture."""
        return {aid: self.derive_attack_surface(aid) for aid in sorted(self.assets.keys())}

    def summarize_topology(self) -> Dict[str, Any]:
        """Return counts and summary metadata of the architecture."""
        return {
            "version": self.version,
            "name": self.name,
            "component_count": len(self.components),
            "interface_count": len(self.interfaces),
            "data_flow_count": len(self.data_flows),
            "trust_zone_count": len(self.trust_zones),
            "trust_boundary_count": len(self.trust_boundaries),
            "asset_count": len(self.assets),
            "trust_boundary_ids": sorted(list(self.trust_boundaries.keys())),
        }
