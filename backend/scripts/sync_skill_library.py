#!/usr/bin/env python3
"""Sync markdown skills into SkillLibrary/SkillToolMapping."""
from __future__ import annotations

from app.db.session import SessionLocal
from app.services.skill_library_service import sync_markdown_skill_library


def main() -> None:
    db = SessionLocal()
    try:
        result = sync_markdown_skill_library(db)
        db.commit()
        print(result)
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
