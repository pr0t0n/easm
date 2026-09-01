import inspect

from app.api import routes_scans


def test_reset_operational_deletes_bas_jobs_before_findings_and_scan_jobs() -> None:
    source = inspect.getsource(routes_scans.reset_operational_scans)
    bas_job_pos = source.index("db.query(BasJob)")
    finding_pos = source.index("db.query(Finding)")
    scan_job_pos = source.index("db.query(ScanJob)", source.index("deleted_scan_jobs"))

    assert bas_job_pos < finding_pos
    assert bas_job_pos < scan_job_pos


def test_reset_operational_deletes_observed_requests_before_endpoint_and_scan_jobs() -> None:
    source = inspect.getsource(routes_scans.reset_operational_scans)
    observed_pos = source.index("db.query(ObservedRequest)")
    endpoint_pos = source.index("db.query(OffensiveEndpoint)")
    scan_job_pos = source.index("db.query(ScanJob)", source.index("deleted_scan_jobs"))

    assert observed_pos < endpoint_pos
    assert observed_pos < scan_job_pos
