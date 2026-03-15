from flask import Blueprint, abort, jsonify, url_for
from flask_login import current_user

from app.models import Skill
from .service import (
    can_access_skill_security_review,
    serialize_skill_security_review,
)

security_review_bp = Blueprint("security_review", __name__)


@security_review_bp.route("/api/security-review/skills/<int:skill_id>", methods=["GET"])
def api_skill_security_review(skill_id: int):
    skill = Skill.query.get_or_404(skill_id)
    if not can_access_skill_security_review(skill, current_user):
        abort(404)
    return jsonify(
        serialize_skill_security_review(
            skill,
            download_url=url_for("skills.download", skill_id=skill.id),
        )
    )
