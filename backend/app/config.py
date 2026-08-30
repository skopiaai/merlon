import os
from pathlib import Path

DB_PATH = Path(os.getenv("SENTINEL_DB_PATH", "/data/sentinel.db"))
ARTIFACT_DIR = Path(os.getenv("SENTINEL_ARTIFACT_DIR", "/data/artifacts"))

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:14b")
OLLAMA_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "180"))

MAX_CONCURRENT_SCANS = int(os.getenv("SENTINEL_MAX_CONCURRENT_SCANS", "2"))

# Global rate ceilings. Individual scans may request less, never more.
MAX_RATE_LIMIT = int(os.getenv("SENTINEL_MAX_RATE_LIMIT", "150"))   # requests/sec
MAX_CONCURRENCY = int(os.getenv("SENTINEL_MAX_CONCURRENCY", "25"))  # parallel conns

ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
