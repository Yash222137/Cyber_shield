import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List
from core.backup.data_scanner import DataScanner
from cryptography.fernet import Fernet

logger = logging.getLogger("DataIsolator")

class DataIsolator:
    """Isolates sensitive files from monitored folders on threat prevention failure."""

    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}
        defense_cfg = self.config.get("defense", {})
        self.isolation_dir = Path(defense_cfg.get("isolation_directory", "./isolated_sensitive_data")).resolve()
        self.scanner = DataScanner(self.config)
        
        self.isolated_files: List[Dict[str, Any]] = []
        self.is_active = False

    def isolate_files(self) -> Dict[str, Any]:
        """Moves and encrypts all critical files to the isolation directory to secure them from threats."""
        if self.is_active:
            return {"status": "already_active", "count": len(self.isolated_files)}

        self.isolation_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate vault key to lock the files
        key = Fernet.generate_key()
        fernet = Fernet(key)
        key_path = self.isolation_dir / ".vault_key"
        key_path.write_bytes(key)

        files = self.scanner.find_critical_files()
        
        manifest: List[Dict[str, Any]] = []
        for file_path in files:
            source = Path(file_path).resolve()
            if not source.is_file() or source == key_path:
                continue

            try:
                # Keep folder structure relative to watched path
                rel_path = self._get_relative_path(source)
                target = self.isolation_dir / rel_path
                # Add .isolated suffix to prevent execution or targeting
                target = target.with_name(target.name + ".isolated")
                
                target.parent.mkdir(parents=True, exist_ok=True)
                
                # Read original, encrypt, write to specific storage, and delete original
                data = source.read_bytes()
                encrypted_data = fernet.encrypt(data)
                target.write_bytes(encrypted_data)
                source.unlink()
                
                manifest.append({
                    "original_path": str(source),
                    "isolated_path": str(target),
                    "filename": source.name,
                    "bytes": target.stat().st_size,
                    "isolated_at": time.strftime("%Y-%m-%d %H:%M:%S")
                })
            except Exception as e:
                logger.error(f"Failed to isolate file {source}: {e}")

        if manifest:
            self.is_active = True
            self.isolated_files = manifest
            logger.warning(f"Data Isolation active: isolated and encrypted {len(manifest)} files to {self.isolation_dir}")
        else:
            if key_path.exists():
                key_path.unlink()
            logger.info("No critical files found to isolate.")

        return {
            "status": "activated" if manifest else "no_files",
            "count": len(manifest),
            "isolated_files": manifest
        }

    def restore_files(self) -> Dict[str, Any]:
        """Restores and decrypts isolated files back to their original locations."""
        if not self.is_active:
            return {"status": "inactive", "count": 0}

        # Load vault key to decrypt the files
        key_path = self.isolation_dir / ".vault_key"
        if not key_path.is_file():
            logger.error("Vault key missing! Cannot decrypt files.")
            return {"status": "error", "message": "Vault key file missing"}

        try:
            key = key_path.read_bytes()
            fernet = Fernet(key)
        except Exception as e:
            logger.error(f"Failed to load vault key: {e}")
            return {"status": "error", "message": f"Failed to load key: {e}"}

        restored_count = 0
        failed_count = 0
        
        for item in self.isolated_files:
            original = Path(item["original_path"])
            isolated = Path(item["isolated_path"])

            if not isolated.is_file():
                failed_count += 1
                continue

            try:
                original.parent.mkdir(parents=True, exist_ok=True)
                
                # Read encrypted, decrypt, and write back to original location
                encrypted_data = isolated.read_bytes()
                decrypted_data = fernet.decrypt(encrypted_data)
                original.write_bytes(decrypted_data)
                
                isolated.unlink()
                restored_count += 1
            except Exception as e:
                logger.error(f"Failed to restore file {isolated} to {original}: {e}")
                failed_count += 1

        # Delete key file
        if key_path.exists():
            try:
                key_path.unlink()
            except Exception as e:
                logger.warning(f"Could not remove key file: {e}")

        # Clean up empty directories in isolation path
        try:
            if self.isolation_dir.exists():
                shutil.rmtree(self.isolation_dir)
        except Exception as e:
            logger.warning(f"Could not remove isolation directory: {e}")

        logger.info(f"Data Isolation restored: {restored_count} files restored, {failed_count} failures.")
        
        self.is_active = False
        self.isolated_files = []
        
        return {
            "status": "restored",
            "restored_count": restored_count,
            "failed_count": failed_count
        }

    def get_status(self) -> Dict[str, Any]:
        return {
            "is_active": self.is_active,
            "isolation_directory": str(self.isolation_dir),
            "isolated_files": self.isolated_files,
            "count": len(self.isolated_files)
        }

    def _get_relative_path(self, source: Path) -> Path:
        # Get watched paths to determine a clean relative path
        for p in self.scanner.critical_paths:
            base_p = Path(p).expanduser().resolve()
            try:
                return source.relative_to(base_p)
            except ValueError:
                continue
        # Fallback to safe pathing
        drive = source.drive.replace(":", "") if source.drive else "root"
        parts = [drive] + [part for part in source.parts if part not in (source.anchor, source.drive)]
        return Path(*parts)
