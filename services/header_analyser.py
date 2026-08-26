from email.message import EmailMessage
from email.utils import parseaddr
from typing import Any
import re


AUTH_PATTERN = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*"
    r"(pass|fail|softfail|neutral|none|temperror|permerror)",
    re.IGNORECASE
)


def extract_domain(address: str) -> str:
    parsed = parseaddr(address or "")[1]

    if "@" not in parsed:
        return ""

    return parsed.rsplit("@", 1)[1].lower().strip()


def analyse_authentication_results(
    message: EmailMessage
) -> dict[str, Any]:
    headers = message.get_all(
        "Authentication-Results",
        []
    )

    results = {
        "spf": "unavailable",
        "dkim": "unavailable",
        "dmarc": "unavailable",
        "authentication_headers_found": len(headers)
    }

    combined = " ".join(headers)

    for mechanism, value in AUTH_PATTERN.findall(combined):
        results[mechanism.lower()] = value.lower()

    return results


def analyse_sender_alignment(
    message: EmailMessage
) -> dict[str, Any]:
    from_address = str(message.get("From", ""))
    reply_to = str(message.get("Reply-To", ""))
    return_path = str(message.get("Return-Path", ""))

    from_domain = extract_domain(from_address)
    reply_to_domain = extract_domain(reply_to)
    return_path_domain = extract_domain(return_path)

    reply_to_mismatch = bool(
        from_domain
        and reply_to_domain
        and from_domain != reply_to_domain
    )

    return_path_mismatch = bool(
        from_domain
        and return_path_domain
        and from_domain != return_path_domain
    )

    return {
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "reply_to_mismatch": reply_to_mismatch,
        "return_path_mismatch": return_path_mismatch
    }


def analyse_headers(
    message: EmailMessage
) -> dict[str, Any]:
    return {
        "authentication": analyse_authentication_results(message),
        "alignment": analyse_sender_alignment(message)
    }
