"""Central configuration loader for AutoTARA AI.

Reads Model_Prompts_Config/config.yaml and provides typed access with sane defaults.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml


def find_project_root() -> Path:
    """Find the root directory of the AutoTARA AI project."""
    # Look for known anchors starting from current directory and parent directories
    current = Path(__file__).resolve().parent
    for parent in [current] + list(current.parents):
        if (parent / "Model_Prompts_Config" / "config.yaml").exists():
            return parent
        if (parent / "PCCOE_STUDENTNAME_PRN_CSX_AIML" / "Model_Prompts_Config" / "config.yaml").exists():
            return parent / "PCCOE_STUDENTNAME_PRN_CSX_AIML"
    # Fallback to current working directory
    cwd = Path.cwd()
    if (cwd / "Model_Prompts_Config" / "config.yaml").exists():
        return cwd
    if (cwd / "PCCOE_STUDENTNAME_PRN_CSX_AIML" / "Model_Prompts_Config" / "config.yaml").exists():
        return cwd / "PCCOE_STUDENTNAME_PRN_CSX_AIML"
    return cwd


class Config:
    """Application configuration holder."""

    def __init__(self, config_dict: Optional[Dict[str, Any]] = None, root_dir: Optional[Path] = None):
        self.root_dir = root_dir or find_project_root()
        self._raw = config_dict or self._load_file()

    def _load_file(self) -> Dict[str, Any]:
        config_path = self.root_dir / "Model_Prompts_Config" / "config.yaml"
        if not config_path.exists():
            # Try finding anywhere relative to root
            candidates = list(self.root_dir.glob("**/Model_Prompts_Config/config.yaml"))
            if candidates:
                config_path = candidates[0]
            else:
                return {}
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    @property
    def project_name(self) -> str:
        return self._raw.get("project", {}).get("name", "AutoTARA AI")

    @property
    def reference_date(self) -> datetime:
        date_str = self._raw.get("project", {}).get("reference_date", "2026-10-13")
        return datetime.strptime(date_str, "%Y-%m-%d")

    @property
    def architecture_dir(self) -> Path:
        rel = self._raw.get("paths", {}).get("architecture_dir", "Input_Data/architecture")
        return self.root_dir / rel

    @property
    def knowledge_base_dir(self) -> Path:
        rel = self._raw.get("paths", {}).get("knowledge_base_dir", "Input_Data/knowledge_base")
        return self.root_dir / rel

    @property
    def freshness_rules(self) -> Dict[str, int]:
        return {
            "current_ahead_days": self._raw.get("freshness", {}).get("current_ahead_days", 30),
            "outdated_overdue_days": self._raw.get("freshness", {}).get("outdated_overdue_days", 180),
        }

    @property
    def retrieval_config(self) -> Dict[str, Any]:
        return self._raw.get("retrieval", {})

    @property
    def llm_config(self) -> Dict[str, Any]:
        return self._raw.get("llm", {})

    @property
    def roles(self) -> List[Dict[str, Any]]:
        return self._raw.get("roles", [])


# Singleton instance
_config_instance: Optional[Config] = None


def get_config(root_dir: Optional[Path] = None, reload: bool = False) -> Config:
    """Get the active configuration instance."""
    global _config_instance
    if _config_instance is None or reload or root_dir is not None:
        _config_instance = Config(root_dir=root_dir)
    return _config_instance
