import inspect

from app.api import routes_scans
from app.models.models import Base, ScanJob


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


def test_reset_operational_handles_every_mapped_scan_job_fk_table() -> None:
    source = inspect.getsource(routes_scans.reset_operational_scans)
    model_by_table = {
        mapper.local_table.name: mapper.class_.__name__
        for mapper in Base.registry.mappers
        if mapper.local_table is not ScanJob.__table__
    }
    fk_tables = {
        table.name
        for table in Base.metadata.tables.values()
        for column in table.columns
        for fk in column.foreign_keys
        if fk.column.table.name == ScanJob.__tablename__
    }
    missing = sorted(
        table
        for table in fk_tables
        if model_by_table.get(table, table) not in source and table not in source
    )

    assert missing == []
