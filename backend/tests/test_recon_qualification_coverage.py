from types import SimpleNamespace


def test_non_public_profile_is_not_materialized():
    from app.services.recon_qualification_coverage import materialize_recon_qualification_coverage

    class Query:
        def filter(self, *_args):
            return self

        def first(self):
            return None

    class Db:
        def __init__(self):
            self.rows = []

        def query(self, *_args):
            return Query()

        def add(self, row):
            self.rows.append(row)

        def flush(self):
            pass

    job = SimpleNamespace(id=12, state_data={"preflight": {"targets": {
        "public.example": {"p02_complete": True, "p06_complete": True, "p06_http_live": True},
        "localhost.example": {"non_public_rejected": True},
    }}})
    db = Db()
    result = materialize_recon_qualification_coverage(db, job)

    assert result == {"targets": 1, "p02": 1, "p06": 1, "rejected": 1}
