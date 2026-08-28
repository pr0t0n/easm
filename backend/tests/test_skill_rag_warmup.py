from app.services import skill_rag_indexer


class _ScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar(self):
        return self.value


class _MappingResult:
    def __init__(self, rows):
        self._rows = rows

    def mappings(self):
        return self

    def all(self):
        return self._rows


class _BackfillDb:
    def __init__(self, pending=2):
        self.pending = pending
        self.updated = 0
        self.commits = 0
        self.rollbacks = 0

    def execute(self, statement, params=None):
        sql = str(statement)
        if "COUNT(*) FROM rag_knowledge_store WHERE embedding IS NULL" in sql:
            return _ScalarResult(self.pending)
        if "SELECT chunk_id, content" in sql:
            return _MappingResult([
                {"chunk_id": "skill:a:0", "content": "first skill"},
                {"chunk_id": "skill:b:0", "content": "second skill"},
            ])
        if "UPDATE rag_knowledge_store" in sql:
            self.updated += 1
            return _ScalarResult(None)
        if "COUNT(*) FROM rag_knowledge_store WHERE embedding IS NOT NULL" in sql:
            return _ScalarResult(self.updated)
        return _ScalarResult(0)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


def test_backfill_missing_embeddings_updates_pending_chunks(monkeypatch):
    from app.services import rag_repository

    db = _BackfillDb()
    monkeypatch.setattr("app.services.embedding_service.is_available", lambda: True)
    monkeypatch.setattr("app.services.embedding_service.embed_texts", lambda texts: [[0.1] * 384 for _ in texts])
    monkeypatch.setattr(rag_repository, "rebuild_embedding_index", lambda **kwargs: None)

    result = rag_repository.backfill_missing_embeddings(limit=20, db=db)

    assert result["available"] is True
    assert result["pending"] == 2
    assert result["updated"] == 2
    assert result["remaining"] == 0
    assert result["errors"] == 0
    assert db.updated == 2
    assert db.commits == 1


def test_backfill_missing_embeddings_reports_unavailable_model(monkeypatch):
    from app.services import rag_repository

    db = _BackfillDb(pending=3)
    monkeypatch.setattr("app.services.embedding_service.is_available", lambda: False)

    result = rag_repository.backfill_missing_embeddings(limit=20, db=db)

    assert result == {"available": False, "pending": 3, "updated": 0, "errors": 0}
    assert db.updated == 0


def test_warm_skill_rag_combines_index_backfill_and_health(monkeypatch):
    monkeypatch.setattr(skill_rag_indexer, "ensure_skill_index_ready", lambda force=False: {"indexed": 0, "errors": 0, "already_ready": True})
    monkeypatch.setattr("app.services.rag_repository.backfill_missing_embeddings", lambda limit=500: {"available": True, "pending": 1, "updated": 1, "errors": 0})
    monkeypatch.setattr("app.services.rag_repository.knowledge_health", lambda: {"ok": True, "issues": []})

    result = skill_rag_indexer.warm_skill_rag(force=False, backfill=True, backfill_limit=50)

    assert result["ok"] is True
    assert result["index"]["already_ready"] is True
    assert result["embedding_backfill"]["updated"] == 1
