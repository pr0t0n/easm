from app.db.session import SessionLocal
from sqlalchemy import text
db = SessionLocal()
print("=== FASES scan #4 (done/total, gate aberto?) ===")
rows = db.execute(text("""
  SELECT phase_id,
    SUM(CASE WHEN status IN ('completed','done') THEN 1 ELSE 0 END) d,
    SUM(CASE WHEN status IN ('dispatched','running','submitted') THEN 1 ELSE 0 END) r,
    SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) b,
    COUNT(*) t
  FROM scan_work_items WHERE scan_job_id=4 GROUP BY phase_id ORDER BY phase_id
""")).fetchall()
for p, d, r, b, t in rows:
    state = "ABERTO" if (d > 0 or r > 0) else ("blocked" if b > 0 else "-")
    print("  %s: %d/%d run=%d blk=%d [%s]" % (p, d, t, r, b, state))
print()
print("=== Ferramentas tunadas — ainda dão timeout? (scan #4) ===")
for tool in ["arjun", "nikto", "sqlmap", "dalfox", "wapiti", "linkfinder", "nuclei-auth-bypass", "nuclei-js-secrets"]:
    rr = dict(db.execute(text("SELECT status, COUNT(*) FROM scan_work_items WHERE scan_job_id=4 AND tool_name=:t GROUP BY status"), {"t": tool}).fetchall())
    if rr:
        print("  %-20s %s" % (tool, rr))
db.close()
