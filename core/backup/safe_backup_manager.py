import hashlib
import json
import logging
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List

from .data_scanner import DataScanner

logger = logging.getLogger("SafeBackupManager")


class SafeBackupManager:
    """Creates local, read-only recovery snapshots for critical files."""

    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}
        backup_cfg = self.config.get("backup", {})
        self.enabled = bool(backup_cfg.get("enabled", True))
        self.destination = Path(backup_cfg.get("local_destination", "./protected_backup")).resolve()
        self.scanner = DataScanner(self.config)
        self.last_snapshot: Dict[str, Any] = {
            "status": "idle",
            "file_count": 0,
            "snapshot_dir": None,
            "created_at": None,
            "manifest": [],
            "reason": None,
        }

    def protect_now(self, reason: str) -> Dict[str, Any]:
        if not self.enabled:
            self.last_snapshot = {
                "status": "disabled",
                "file_count": 0,
                "snapshot_dir": None,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "manifest": [],
                "reason": reason,
            }
            return self.last_snapshot

        files = self.scanner.find_critical_files()
        snapshot_id = time.strftime("%Y%m%d_%H%M%S")
        snapshot_dir = self.destination / snapshot_id
        snapshot_dir.mkdir(parents=True, exist_ok=True)

        manifest: List[Dict[str, Any]] = []
        for file_path in files:
            source = Path(file_path).resolve()
            if not source.is_file():
                continue

            target = snapshot_dir / self._safe_relative_path(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            manifest.append({
                "source": str(source),
                "backup": str(target),
                "sha256": self._sha256(target),
                "bytes": target.stat().st_size,
            })

        manifest_path = snapshot_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        status = "created" if manifest else "created_empty"
        self.last_snapshot = {
            "status": status,
            "file_count": len(manifest),
            "snapshot_dir": str(snapshot_dir),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "manifest": manifest,
            "reason": reason,
            "message": "No critical files matched backup rules." if not manifest else "Critical files copied.",
        }
        logger.info("Created protection snapshot with %s files: %s", len(manifest), snapshot_dir)
        return self.last_snapshot

    def get_status(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "destination": str(self.destination),
            "last_snapshot": self.last_snapshot,
        }

    def _safe_relative_path(self, source: Path) -> Path:
        drive = source.drive.replace(":", "") if source.drive else "root"
        parts = [drive] + [part for part in source.parts if part not in (source.anchor, source.drive)]
        return Path(*parts)

    def _sha256(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
