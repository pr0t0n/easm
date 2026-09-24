from app.db.session import SessionLocal
from app.models.models import User
from app.schemas.scan import ScanCreate
from app.api.routes_scans import create_scan

db = SessionLocal()
try:
    admin = db.query(User).filter(User.email == "admin@example.com").first()
    if not admin:
        raise SystemExit("admin user not found")

    payload = ScanCreate(
        target_query="http://juice_shop:3000",
        mode="single",
        execution_plan="external_only",
        scan_level="aggressive",
        scope_authorization_attested=True,
        access_group_id=1,
    )
    result = create_scan(payload, db=db, current_user=admin)
    print("SCAN_ID", result.id)
    print("STATUS", result.status)
    print("COMPLIANCE", result.compliance_status)
    print("CURRENT_STEP", result.current_step)
finally:
    db.close()
