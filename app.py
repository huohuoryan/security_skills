import os
import tempfile

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

try:
    from .engine import build_skill_security_review
except ImportError:
    from engine import build_skill_security_review

MAX_UPLOAD_BYTES = 10 * 1024 * 1024


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.post("/api/review")
    def review_archive():
        upload = request.files.get("archive")
        if upload is None or not str(upload.filename or "").strip():
            return jsonify({"ok": False, "error": "Please choose a ZIP file before starting the review."}), 400

        filename = secure_filename(str(upload.filename or "archive.zip"))
        if os.path.splitext(filename.lower())[1] != ".zip":
            return jsonify({"ok": False, "error": "Only .zip archives are supported right now."}), 400

        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        temp_path = temp_file.name
        temp_file.close()

        try:
            upload.save(temp_path)
            review = build_skill_security_review(temp_path)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

        return jsonify(
            {
                "ok": True,
                "filename": filename,
                **review,
            }
        )

    @app.errorhandler(RequestEntityTooLarge)
    def handle_file_too_large(_error):
        return jsonify({"ok": False, "error": "The uploaded file is too large. The current limit is 10 MB."}), 413

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)


