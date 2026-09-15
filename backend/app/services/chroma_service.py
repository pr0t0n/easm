from __future__ import annotations

import fcntl
import os
import threading
from pathlib import Path

import chromadb
from chromadb.config import Settings


class FalsePositiveVectorStore:
    def __init__(self, persist_path: str | None = None):
        self.persist_path = str(persist_path or os.getenv("CHROMA_PERSIST_PATH") or "/tmp/chroma")
        self.client = None
        self.collection = None
        self._lock = threading.Lock()

    def _collection(self):
        if self.collection is not None:
            return self.collection
        with self._lock:
            if self.collection is not None:
                return self.collection
            path = Path(self.persist_path)
            path.mkdir(parents=True, exist_ok=True)
            lock_path = path / ".initialization.lock"
            with lock_path.open("a+") as lock_file:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                self.client = chromadb.PersistentClient(
                    path=str(path),
                    settings=Settings(anonymized_telemetry=False),
                )
                self.collection = self.client.get_or_create_collection("false_positives")
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            return self.collection

    def add_false_positive(self, item_id: str, text: str, metadata: dict):
        self._collection().upsert(documents=[text], metadatas=[metadata], ids=[item_id])

    def remove_false_positive(self, item_id: str):
        try:
            self._collection().delete(ids=[item_id])
        except Exception:
            pass

    def search_similar(self, text: str, top_k: int = 3):
        return self._collection().query(query_texts=[text], n_results=top_k)
