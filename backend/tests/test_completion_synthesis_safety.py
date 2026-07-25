import inspect


def test_embeddings_do_not_download_at_runtime_by_default() -> None:
    from app.services import embedding_service

    assert embedding_service.EMBED_ALLOW_RUNTIME_DOWNLOAD is False

    source = inspect.getsource(embedding_service._get_model)
    assert "if not EMBED_ALLOW_RUNTIME_DOWNLOAD" in source
    assert "_load_failed = True" in source
    assert "return None" in source


def test_dispatcher_commits_terminal_state_before_pentest_synthesis() -> None:
    from app.workers import tasks

    source = inspect.getsource(tasks.dispatch_scan_work_items)
    completion_pos = source.index("SCAN CONCLUÍDO via work_queue_dispatcher")
    commit_pos = source.index("db.commit()", completion_pos)
    synth_pos = source.index("synthesize_pentest", commit_pos)

    assert completion_pos < commit_pos < synth_pos
