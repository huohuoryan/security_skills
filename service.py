from app.archive_storage import ensure_archive_local
from app.models import Skill

from .engine import build_skill_security_review


def can_access_skill_security_review(skill: Skill, user) -> bool:
    if bool(getattr(skill, "is_published", False)):
        return True
    if not bool(getattr(user, "is_authenticated", False)):
        return False
    return bool(getattr(user, "is_admin", False) or getattr(user, "id", None) == getattr(skill, "user_id", None))


def serialize_skill_security_review(skill: Skill, download_url: str) -> dict:
    abs_path = ensure_archive_local(skill.file_path)
    review = build_skill_security_review(abs_path)
    return {
        "ok": True,
        "skill_id": int(skill.id),
        "skill_title": skill.title or "",
        "download_url": download_url,
        "overall_level": (review.get("overall_level") or "low"),
        "risk_score": int(review.get("risk_score") or 0),
        "risk_counts": review.get("risk_counts") or {"high": 0, "medium": 0, "low": 0},
        "checks": list(review.get("checks") or []),
        "archive": review.get("archive") or {},
        "highlights": review.get("highlights") or {},
        "issue_count": int(review.get("issue_count") or 0),
        "observation_count": int(review.get("observation_count") or 0),
        "issues": list(review.get("issues") or [])[:14],
        "observations": list(review.get("observations") or [])[:14],
        "risks": list(review.get("risks") or [])[:14],
    }
