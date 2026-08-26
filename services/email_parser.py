from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from typing import Any


def extract_email_body(message: EmailMessage) -> str:
    plain_parts: list[str] = []
    html_parts: list[str] = []

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            disposition = str(
                part.get("Content-Disposition", "")
            ).lower()

            if "attachment" in disposition:
                continue

            try:
                content = part.get_content()
            except Exception:
                continue

            if content_type == "text/plain":
                plain_parts.append(str(content))
            elif content_type == "text/html":
                html_parts.append(str(content))
    else:
        try:
            content = str(message.get_content())
        except Exception:
            content = ""

        if message.get_content_type() == "text/plain":
            plain_parts.append(content)
        elif message.get_content_type() == "text/html":
            html_parts.append(content)

    if plain_parts:
        return "\n".join(plain_parts)

    return "\n".join(html_parts)


def extract_attachments(
    message: EmailMessage
) -> list[dict[str, Any]]:
    attachments: list[dict[str, Any]] = []

    for index, part in enumerate(message.iter_attachments(), start=1):
        filename = part.get_filename() or f"attachment_{index}"
        payload = part.get_payload(decode=True) or b""

        attachments.append({
            "filename": filename,
            "content_type": part.get_content_type(),
            "size_bytes": len(payload),
            "payload": payload
        })

    return attachments


def parse_eml_file(file_path: Path) -> dict[str, Any]:
    with file_path.open("rb") as file:
        message = BytesParser(
            policy=policy.default
        ).parse(file)

    body = extract_email_body(message)

    return {
        "message": message,
        "sender": str(message.get("From", "")),
        "recipient": str(message.get("To", "")),
        "subject": str(message.get("Subject", "")),
        "date": str(message.get("Date", "")),
        "reply_to": str(message.get("Reply-To", "")),
        "return_path": str(message.get("Return-Path", "")),
        "message_id": str(message.get("Message-ID", "")),
        "body": body,
        "attachments": extract_attachments(message)
    }
