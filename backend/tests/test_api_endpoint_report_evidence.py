from app.services.api_endpoint_report import _representative_evidence


def _row(status: int) -> dict:
    return {"response_status": status, "curl": f"curl example/{status}"}


def test_representative_evidence_preserves_distinct_http_statuses():
    rows = [_row(401) for _ in range(28)] + [_row(403) for _ in range(9)] + [_row(404)] + [_row(431) for _ in range(3)]

    selected = _representative_evidence(rows, limit=10)
    statuses = [row["response_status"] for row in selected]

    assert set(statuses) == {401, 403, 404, 431}
    assert len(selected) == 10


def test_representative_evidence_respects_limit_when_more_statuses_exist():
    rows = [_row(status) for status in range(100, 120)]

    selected = _representative_evidence(rows, limit=4)

    assert [row["response_status"] for row in selected] == [100, 101, 102, 103]
