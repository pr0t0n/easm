from types import SimpleNamespace


class _EmptyQuery:
    def filter(self, *_args, **_kwargs):
        return self

    def first(self):
        return None


class _FakeDb:
    def __init__(self):
        self.new = []

    def query(self, *_args):
        return _EmptyQuery()


def test_coverage_is_scoped_to_finding_when_asset_is_shared():
    from app.services.finding_validation_lifecycle import _coverage_row

    db = _FakeDb()
    job = SimpleNamespace(id=12)
    first = _coverage_row(db, job, SimpleNamespace(id=16054), "toligado.valid.com")
    db.new.append(first)
    second = _coverage_row(db, job, SimpleNamespace(id=16055), "toligado.valid.com")

    assert first.target_ref == "finding:16054"
    assert second.target_ref == "finding:16055"
    assert first.target_ref != second.target_ref


def test_coverage_reuses_pending_row_for_same_finding():
    from app.services.finding_validation_lifecycle import _coverage_row

    db = _FakeDb()
    job = SimpleNamespace(id=12)
    first = _coverage_row(db, job, SimpleNamespace(id=16054), "toligado.valid.com")
    db.new.append(first)

    assert _coverage_row(db, job, SimpleNamespace(id=16054), "toligado.valid.com") is first
