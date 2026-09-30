import os
import time
import threading
import logging
from typing import Dict, List, Any
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger("FileMonitor")

class FileSystemHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback

    def on_created(self, event):
        if not event.is_directory:
            self.callback("CREATED", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.callback("MODIFIED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.callback("DELETED", event.src_path)

class FileMonitor:
    def __init__(self, config: Dict[str, Any]):
        self.config = config.get("file", {})
        self.watch_path = os.path.abspath(self.config.get("watch_path", "./monitored_directory"))
        self.running = False
        
        self.stats_lock = threading.Lock()
        self.observer = None
        
        # Keep track of file events
        self.event_history = []
        self.modification_rate = 0.0 # events per minute
        self.event_timestamps = []
        
        self.simulated_attack_type = None

    def start(self):
        # Create directory if it doesn't exist
        os.makedirs(self.watch_path, exist_ok=True)
        
        self.running = True
        self.observer = Observer()
        handler = FileSystemHandler(self._handle_event)
        self.observer.schedule(handler, self.watch_path, recursive=True)
        self.observer.start()
        
        # Start rate decay thread
        self.decay_thread = threading.Thread(target=self._decay_loop, daemon=True)
        self.decay_thread.start()
        
        logger.info(f"File Monitor started watching path: {self.watch_path}")

    def stop(self):
        self.running = False
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=2.0)
        logger.info("File Monitor stopped.")

    def _handle_event(self, event_type: str, filepath: str):
        now = time.time()
        filename = os.path.basename(filepath)
        
        with self.stats_lock:
            self.event_timestamps.append(now)
            self.event_history.insert(0, {
                "timestamp": time.strftime("%H:%M:%S", time.localtime(now)),
                "type": event_type,
                "filename": filename,
                "path": filepath
            })
            # Limit history to 50 items
            self.event_history = self.event_history[:50]

    def _decay_loop(self):
        while self.running:
            now = time.time()
            with self.stats_lock:
                # Keep timestamps in the last 60 seconds
                self.event_timestamps = [t for t in self.event_timestamps if now - t < 60.0]
                self.modification_rate = len(self.event_timestamps)
                
                # Injection patterns for simulation
                if self.simulated_attack_type == "Ransomware":
                    # Ransomware: extremely high file modifications count
                    self.modification_rate = max(self.modification_rate, 142)
                    if not self.event_history or self.event_history[0].get("filename") != "critical_data.docx.locked":
                        self.event_history.insert(0, {
                            "timestamp": time.strftime("%H:%M:%S", time.localtime(now)),
                            "type": "MODIFIED",
                            "filename": "critical_data.docx.locked",
                            "path": os.path.join(self.watch_path, "critical_data.docx.locked")
                        })
            time.sleep(1.0)

    def trigger_simulated_attack(self, attack_type: str):
        with self.stats_lock:
            self.simulated_attack_type = attack_type

    def get_features(self) -> Dict[str, Any]:
        """Extract features to pass to the AI detector model."""
        with self.stats_lock:
            return {
                "file_modification_rate": self.modification_rate
            }

    def get_status(self) -> Dict[str, Any]:
        with self.stats_lock:
            return {
                "watch_path": self.watch_path,
                "modification_rate": self.modification_rate,
                "event_history": self.event_history
            }
