from pathlib import Path
from typing import Any
import uuid

from flask import Flask, render_template, request
from werkzeug.utils import secure_filename

from services.email_parser import parse_eml_file
from services.ml_analyser import MLAnalyser
from services.header_analyser import analyse_headers
from services.url_analyser import analyse_urls
from services.attachment_analyser import analyse_attachments
from services.sandbox_analyser import (
    enrich_urls_with_sandbox,
)
from services.risk_engine import calculate_risk


BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = (
    BASE_DIR
    / "models"
    / "phishing_email_detection_pipeline.joblib"
)

UPLOAD_FOLDER = BASE_DIR / "uploads"

ALLOWED_EXTENSIONS = {".eml"}

MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB


UPLOAD_FOLDER.mkdir(
    parents=True,
    exist_ok=True
)


app = Flask(__name__)

app.config["UPLOAD_FOLDER"] = str(
    UPLOAD_FOLDER
)

app.config["MAX_CONTENT_LENGTH"] = (
    MAX_UPLOAD_SIZE
)


ml_analyser = MLAnalyser(
    MODEL_PATH
)


def allowed_file(filename: str) -> bool:
    """
    Check whether the uploaded file uses an allowed extension.
    """
    return (
        Path(filename).suffix.lower()
        in ALLOWED_EXTENSIONS
    )


def safe_attachment_view(
    attachments: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """
    Remove raw attachment payloads before sending data
    to the HTML template.
    """
    safe_items = []

    for attachment in attachments:
        safe_items.append({
            key: value
            for key, value in attachment.items()
            if key != "payload"
        })

    return safe_items


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None

    if request.method == "POST":
        uploaded_file = request.files.get(
            "email_file"
        )

        if uploaded_file is None:
            error = "No email file was provided."

        elif uploaded_file.filename == "":
            error = "Please select an .eml file."

        elif not allowed_file(
            uploaded_file.filename
        ):
            error = (
                "Only .eml email files are accepted."
            )

        else:
            original_filename = secure_filename(
                uploaded_file.filename
            )

            unique_filename = (
                f"{uuid.uuid4().hex}_"
                f"{original_filename}"
            )

            saved_path = (
                Path(
                    app.config["UPLOAD_FOLDER"]
                )
                / unique_filename
            )

            try:
                uploaded_file.save(
                    saved_path
                )

                email_data = parse_eml_file(
                    saved_path
                )

                ml_result = ml_analyser.analyse(
                    sender=email_data["sender"],
                    recipient=email_data[
                        "recipient"
                    ],
                    subject=email_data["subject"],
                    body=email_data["body"]
                )

                header_result = analyse_headers(
                    email_data["message"]
                )

                url_results = analyse_urls(
                    email_data["body"]
                )


                url_results = enrich_urls_with_sandbox(
                    url_results=url_results,
                    screenshot_directory=(
                        BASE_DIR
                        / "static"
                        / "sandbox"
                    ),
                )

                attachment_results = (
                    analyse_attachments(
                        email_data[
                            "attachments"
                        ]
                    )
                )

                risk_result = calculate_risk(
                    ml_result=ml_result,
                    header_result=header_result,
                    url_results=url_results,
                    attachment_results=(
                        attachment_results
                    )
                )

                result = {
                    "filename": original_filename,

                    "email": {
                        "sender": (
                            email_data["sender"]
                        ),
                        "recipient": (
                            email_data["recipient"]
                        ),
                        "subject": (
                            email_data["subject"]
                        ),
                        "date": (
                            email_data["date"]
                        ),
                        "reply_to": (
                            email_data["reply_to"]
                        ),
                        "return_path": (
                            email_data[
                                "return_path"
                            ]
                        ),
                        "message_id": (
                            email_data[
                                "message_id"
                            ]
                        ),
                        "body_preview": (
                            email_data["body"][
                                :1000
                            ]
                        )
                    },

                    "ml": ml_result,

                    "headers": header_result,

                    "urls": url_results,

                    "attachments": (
                        safe_attachment_view(
                            attachment_results
                        )
                    ),

                    "risk": risk_result
                }

            except Exception as exc:
                app.logger.exception(
                    "Email analysis failed"
                )

                error = (
                    "Unable to analyse the email: "
                    f"{exc}"
                )

            finally:
                if saved_path.exists():
                    saved_path.unlink()

    return render_template(
        "index.html",
        result=result,
        error=error
    )


@app.errorhandler(413)
def file_too_large(error):
    return (
        render_template(
            "index.html",
            result=None,
            error=(
                "The uploaded file exceeds "
                "the 10 MB limit."
            )
        ),
        413
    )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
