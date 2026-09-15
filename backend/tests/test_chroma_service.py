from unittest.mock import MagicMock

from app.services.chroma_service import FalsePositiveVectorStore


def test_vector_store_initializes_lazily_and_disables_telemetry(monkeypatch, tmp_path):
    collection = MagicMock()
    client = MagicMock()
    client.get_or_create_collection.return_value = collection
    factory = MagicMock(return_value=client)
    monkeypatch.setattr("app.services.chroma_service.chromadb.PersistentClient", factory)

    store = FalsePositiveVectorStore(str(tmp_path))

    factory.assert_not_called()
    store.add_false_positive("fp-1", "signature", {"finding_id": 1})
    store.search_similar("signature", 2)

    factory.assert_called_once()
    assert factory.call_args.kwargs["settings"].anonymized_telemetry is False
    collection.upsert.assert_called_once()
    collection.query.assert_called_once_with(query_texts=["signature"], n_results=2)
