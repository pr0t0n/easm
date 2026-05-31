from app.db.session import SessionLocal
from sqlalchemy import text
from app.models.models import Finding, ScanWorkItem
from sqlalchemy import func
import sys
sid = int(sys.argv[1]) if len(sys.argv) > 1 else 4
db = SessionLocal()
j = db.execute(text("SELECT status, mission_progress FROM scan_jobs WHERE id=:s"), {"s": sid}).first()
c = dict(db.execute(text("SELECT status,COUNT(*) FROM scan_work_items WHERE scan_job_id=:s GROUP BY status"), {"s": sid}).fetchall())
tot = sum(c.values())
done = c.get("completed", 0) + c.get("done", 0)
run = c.get("dispatched", 0) + c.get("running", 0) + c.get("submitted", 0)
print("Scan #%d: %s %s%% | wq=%d done=%d run=%d q=%d blk=%d skip=%d fail=%d tout=%d" % (
    sid, j[0], j[1], tot, done, run, c.get("queued", 0), c.get("blocked", 0),
    c.get("skipped", 0), c.get("failed", 0), c.get("timeout", 0)))
# learning-seeded items (ITEM 3)
ls = db.execute(text("SELECT COUNT(*) FROM scan_work_items WHERE scan_job_id=:s AND tool_name IN (SELECT tool_name FROM scan_work_items WHERE scan_job_id=:s)"), {"s": sid}).scalar()
from sqlalchemy import cast, String
h1 = db.execute(text("SELECT COUNT(*) FROM scan_work_items WHERE scan_job_id=:s AND metadata->>'source'='hackerone_learnings'"), {"s": sid}).scalar()
findings = db.query(func.count(Finding.id)).filter(Finding.scan_job_id == sid).scalar()
vulns = db.execute(text("SELECT COUNT(*) FROM vulnerabilities v JOIN assets a ON a.id=v.asset_id WHERE (v.metadata->>'scan_id')=:s"), {"s": str(sid)}).scalar()
print("   findings=%d | hackerone_seeded=%d | vulnerabilities(scan)=%s" % (findings, h1, vulns))
db.close()
