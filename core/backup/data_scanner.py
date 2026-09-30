import logging
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List

logger = logging.getLogger("DataScanner")

class DataScanner:
    DEFAULT_SENSITIVE_EXTENSIONS = {
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".pdf",
        ".txt",
        ".csv",
        ".db",
        ".sqlite",
        ".key",
        ".pem",
    }

    EXCLUDED_CRITICAL_EXTENSIONS = {
        ".json",
        ".yaml",
        ".yml",
        ".ini",
        ".conf",
        ".py",
        ".exe",
        ".dll",
        ".sys",
        ".bat",
        ".sh",
        ".cmd",
        ".msi",
    }

    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}
        backup_cfg = self.config.get("backup", {})
        file_cfg = self.config.get("file", {})
        monitor_cfg = self.config.get("monitors", {}).get("file", {})

        configured_paths = backup_cfg.get("critical_paths") or []
        fallback_path = file_cfg.get("watch_path") or monitor_cfg.get("watch_path") or "./monitored_directory"
        self.critical_paths = configured_paths or [fallback_path]
        self.max_file_size_mb = float(backup_cfg.get("max_file_size_mb", 50))
        extensions = backup_cfg.get("critical_extensions") or sorted(self.DEFAULT_SENSITIVE_EXTENSIONS)
        
        # Exclude critical extensions to make sure critical configuration files are never selected
        self.critical_extensions = {ext.lower() for ext in extensions if ext.lower() not in self.EXCLUDED_CRITICAL_EXTENSIONS}

        logger.info("Data Scanner initialized for sensitive file discovery.")

    def find_critical_files(self) -> list:
        files: List[str] = []
        for base_path in self._iter_existing_paths(self.critical_paths):
            if base_path.is_file():
                if self._is_critical_file(base_path):
                    files.append(str(base_path))
                continue

            for root, _, filenames in os.walk(base_path):
                for filename in filenames:
                    candidate = Path(root) / filename
                    if self._is_critical_file(candidate):
                        files.append(str(candidate))

        return sorted(set(files))

    def _iter_existing_paths(self, paths: Iterable[str]) -> Iterable[Path]:
        for raw_path in paths:
            path = Path(raw_path).expanduser().resolve()
            if path.exists():
                yield path
            else:
                logger.warning("Critical path does not exist and will be skipped: %s", path)

    def _is_critical_file(self, path: Path) -> bool:
        try:
            suffix = path.suffix.lower()
            if suffix in self.EXCLUDED_CRITICAL_EXTENSIONS:
                return False
            if path.name.lower() in ("settings.yaml", "manifest.json", "package.json"):
                return False
            if suffix not in self.critical_extensions:
                return False
            max_bytes = self.max_file_size_mb * 1024 * 1024
            return path.stat().st_size <= max_bytes
        except OSError:
            return False
