from typing import Any


RISK_ORDER = {
    "Low": 1,
    "Medium": 2,
    "High": 3
}


def _normalise_risk_level(value: Any) -> str:
    """
    Convert an analyser risk value into Low, Medium, or High.
    Unknown values default to Low.
    """
    normalised = str(value or "").strip().lower()

    if normalised == "high":
        return "High"

    if normalised == "medium":
        return "Medium"

    return "Low"


def _highest_risk_level(
    results: list[dict[str, Any]]
) -> str:
    """
    Return the highest risk level found in a list of analyser results.
    """
    highest = "Low"

    for result in results:
        current = _normalise_risk_level(
            result.get("risk_level")
        )

        if RISK_ORDER[current] > RISK_ORDER[highest]:
            highest = current

    return highest


def calculate_risk(
    ml_result: dict[str, Any],
    header_result: dict[str, Any],
    url_results: list[dict[str, Any]],
    attachment_results: list[dict[str, Any]]
) -> dict[str, Any]:
    """
    Combine ML, header, URL, and attachment findings.

    Machine-learning output:
    - Legitimate
    - Phishing

    Overall hybrid output:
    - Legitimate
    - Suspicious
    - Phishing

    Important:
    The score is a prototype rule-based value, not a probability.
    High-risk URLs and attachments trigger minimum-classification
    overrides so dangerous evidence cannot be labelled Legitimate.
    """

    score = 0
    indicators: list[str] = []
    override_reasons: list[str] = []

    # =========================================================
    # 1. Machine-learning analysis
    # =========================================================
    ml_is_phishing = (
        int(ml_result.get("numeric_label", 0)) == 1
    )

    if ml_is_phishing:
        score += 45
        indicators.append(
            "Machine-learning model classified the email as phishing"
        )
    else:
        indicators.append(
            "Machine-learning model classified the email as legitimate"
        )

    # =========================================================
    # 2. Header authentication and sender alignment
    # =========================================================
    authentication = header_result.get(
        "authentication",
        {}
    )

    alignment = header_result.get(
        "alignment",
        {}
    )

    spf_result = str(
        authentication.get("spf", "unavailable")
    ).lower()

    dkim_result = str(
        authentication.get("dkim", "unavailable")
    ).lower()

    dmarc_result = str(
        authentication.get("dmarc", "unavailable")
    ).lower()

    authentication_failure_count = 0

    if spf_result == "fail":
        score += 12
        authentication_failure_count += 1
        indicators.append("SPF authentication failed")

    elif spf_result == "softfail":
        score += 7
        indicators.append("SPF returned softfail")

    elif spf_result in {"temperror", "permerror"}:
        score += 5
        indicators.append(
            f"SPF returned {spf_result}"
        )

    if dkim_result == "fail":
        score += 12
        authentication_failure_count += 1
        indicators.append("DKIM verification failed")

    elif dkim_result in {"temperror", "permerror"}:
        score += 5
        indicators.append(
            f"DKIM returned {dkim_result}"
        )

    if dmarc_result == "fail":
        score += 18
        authentication_failure_count += 1
        indicators.append("DMARC authentication failed")

    elif dmarc_result in {"temperror", "permerror"}:
        score += 7
        indicators.append(
            f"DMARC returned {dmarc_result}"
        )

    reply_to_mismatch = bool(
        alignment.get("reply_to_mismatch", False)
    )

    return_path_mismatch = bool(
        alignment.get("return_path_mismatch", False)
    )

    if reply_to_mismatch:
        score += 10
        indicators.append(
            "Reply-To domain differs from the From domain"
        )

    if return_path_mismatch:
        score += 6
        indicators.append(
            "Return-Path domain differs from the From domain"
        )

    # =========================================================
    # 3. URL analysis
    # =========================================================
    suspicious_urls = [
        result
        for result in url_results
        if result.get("suspicious", False)
    ]

    highest_url_risk = _highest_risk_level(
        suspicious_urls
    )

    highest_url_score = max(
        (
            int(result.get("risk_score", 0))
            for result in suspicious_urls
        ),
        default=0
    )

    if suspicious_urls:
        url_contribution = min(
            20,
            round(highest_url_score * 0.4)
            + min(6, len(suspicious_urls) * 2)
        )

        score += url_contribution

        indicators.append(
            f"{len(suspicious_urls)} suspicious URL(s) detected"
        )

    # =========================================================
    # 4. Attachment analysis
    # =========================================================
    suspicious_attachments = [
        result
        for result in attachment_results
        if result.get("suspicious", False)
    ]

    highest_attachment_risk = _highest_risk_level(
        suspicious_attachments
    )

    highest_attachment_score = max(
        (
            int(result.get("risk_score", 0))
            for result in suspicious_attachments
        ),
        default=0
    )

    if suspicious_attachments:
        attachment_contribution = min(
            25,
            round(highest_attachment_score * 0.4)
            + min(
                6,
                len(suspicious_attachments) * 2
            )
        )

        score += attachment_contribution

        indicators.append(
            f"{len(suspicious_attachments)} "
            "suspicious attachment(s) detected"
        )

    # Keep score within 0-100.
    score = min(
        max(score, 0),
        100
    )

    # =========================================================
    # 5. Base classification from score
    # =========================================================
    if score >= 70:
        risk_level = "High"
        overall_classification = "Phishing"

    elif score >= 35:
        risk_level = "Medium"
        overall_classification = "Suspicious"

    else:
        risk_level = "Low"
        overall_classification = "Legitimate"

    # =========================================================
    # 6. Safety override rules
    # =========================================================

    # Rule A:
    # A high-risk attachment must never be labelled Legitimate.
    if highest_attachment_risk == "High":
        override_reasons.append(
            "High-risk attachment triggered a minimum "
            "classification of Suspicious"
        )

        if overall_classification == "Legitimate":
            overall_classification = "Suspicious"
            risk_level = "Medium"

    # Rule B:
    # A high-risk URL must never be labelled Legitimate.
    if highest_url_risk == "High":
        override_reasons.append(
            "High-risk URL triggered a minimum "
            "classification of Suspicious"
        )

        if overall_classification == "Legitimate":
            overall_classification = "Suspicious"
            risk_level = "Medium"

    # Rule C:
    # If ML says phishing and there is strong supporting evidence,
    # classify the email as Phishing even when the score is below 70.
    strong_supporting_evidence = any([
        highest_attachment_risk == "High",
        highest_url_risk == "High",
        authentication_failure_count >= 1,
        reply_to_mismatch
    ])

    if ml_is_phishing and strong_supporting_evidence:
        overall_classification = "Phishing"
        risk_level = "High"

        override_reasons.append(
            "Phishing ML prediction was supported by "
            "additional high-confidence indicators"
        )

    # Rule D:
    # Two or more authentication failures plus a high-risk URL
    # or attachment should be treated as Phishing.
    severe_authentication_combination = (
        authentication_failure_count >= 2
        and (
            highest_attachment_risk == "High"
            or highest_url_risk == "High"
        )
    )

    if severe_authentication_combination:
        overall_classification = "Phishing"
        risk_level = "High"

        override_reasons.append(
            "Multiple authentication failures combined with "
            "high-risk content triggered a Phishing classification"
        )

    # Rule E:
    # A dangerous attachment with a strong score plus sender mismatch
    # should be classified as Phishing.
    dangerous_attachment_combination = (
        highest_attachment_risk == "High"
        and highest_attachment_score >= 30
        and (
            reply_to_mismatch
            or return_path_mismatch
            or authentication_failure_count >= 1
        )
    )

    if dangerous_attachment_combination:
        overall_classification = "Phishing"
        risk_level = "High"

        override_reasons.append(
            "High-risk attachment combined with sender or "
            "authentication inconsistency triggered Phishing"
        )

    # Add override explanations to the dashboard findings.
    indicators.extend(override_reasons)

    return {
        "score": score,
        "risk_level": risk_level,
        "overall_classification": overall_classification,
        "indicators": indicators,
        "override_applied": bool(override_reasons),
        "override_reasons": override_reasons,
        "suspicious_url_count": len(
            suspicious_urls
        ),
        "suspicious_attachment_count": len(
            suspicious_attachments
        ),
        "highest_url_risk": highest_url_risk,
        "highest_url_score": highest_url_score,
        "highest_attachment_risk": (
            highest_attachment_risk
        ),
        "highest_attachment_score": (
            highest_attachment_score
        ),
        "authentication_failure_count": (
            authentication_failure_count
        )
    }
