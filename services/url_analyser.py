from collections import Counter
from typing import Any
from urllib.parse import urlparse, unquote
import ipaddress
import math
import re


URL_PATTERN = re.compile(
    r"""(?ix)
    \b(
        https?://
        [^\s<>"'\]\[(){}]+
    )
    """
)


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
    "rebrand.ly",
    "shorturl.at"
}


# Treat this only as one indicator. A TLD alone must never prove phishing.
HIGHER_RISK_TLDS = {
    ".zip",
    ".mov",
    ".click",
    ".top",
    ".xyz",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".work",
    ".support",
    ".rest",
    ".cam",
    ".country"
}


PHISHING_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "password",
    "bank",
    "payment",
    "invoice",
    "confirm",
    "wallet",
    "suspend",
    "unlock"
}


BRAND_TERMS = {
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "whatsapp",
    "maybank",
    "cimb",
    "publicbank",
    "rhb",
    "bankislam"
}


MAX_REASONABLE_URL_LENGTH = 100
MAX_REASONABLE_HOSTNAME_LENGTH = 60
MAX_REASONABLE_SUBDOMAINS = 3
HIGH_ENTROPY_THRESHOLD = 4.2


def extract_urls(text: str) -> list[str]:
    """
    Extract and deduplicate HTTP/HTTPS URLs.
    """
    urls = URL_PATTERN.findall(
        text or ""
    )

    cleaned_urls = {
        url.rstrip(
            ".,;:!?\"'"
        )
        for url in urls
    }

    return sorted(cleaned_urls)


def hostname_is_ip(
    hostname: str
) -> bool:
    """
    Return True if the hostname is an IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(
            hostname
        )
        return True

    except ValueError:
        return False


def calculate_shannon_entropy(
    value: str
) -> float:
    """
    Calculate Shannon entropy for a string.

    High entropy can indicate random-looking paths or query values,
    but it is only a supporting indicator.
    """
    if not value:
        return 0.0

    frequencies = Counter(
        value
    )

    length = len(value)

    entropy = -sum(
        (count / length)
        * math.log2(count / length)
        for count in frequencies.values()
    )

    return round(
        entropy,
        4
    )


def get_domain_parts(
    hostname: str
) -> list[str]:
    """
    Split a hostname into non-empty labels.
    """
    return [
        part
        for part in hostname.split(".")
        if part
    ]


def count_subdomains(
    hostname: str
) -> int:
    """
    Estimate subdomain count.

    This lightweight prototype assumes the final two labels are the
    registered domain and suffix. It is not a public-suffix resolver.
    """
    labels = get_domain_parts(
        hostname
    )

    return max(
        0,
        len(labels) - 2
    )


def contains_non_ascii(
    value: str
) -> bool:
    """
    Identify Unicode characters that may require closer inspection.
    """
    return any(
        ord(character) > 127
        for character in value
    )


def find_keywords(
    value: str,
    keywords: set[str]
) -> list[str]:
    """
    Return keyword matches from a URL component.
    """
    lower_value = value.lower()

    return sorted(
        keyword
        for keyword in keywords
        if keyword in lower_value
    )


def analyse_url(
    url: str
) -> dict[str, Any]:
    """
    Perform lightweight static URL analysis.
    """
    decoded_url = unquote(
        url
    )

    parsed = urlparse(
        decoded_url
    )

    hostname = (
        parsed.hostname or ""
    ).lower()

    path_and_query = (
        f"{parsed.path}?"
        f"{parsed.query}"
    )

    indicators: list[str] = []
    risk_points = 0

    if parsed.scheme.lower() != "https":
        indicators.append(
            "URL does not use HTTPS"
        )
        risk_points += 8

    if not hostname:
        indicators.append(
            "URL hostname is missing or malformed"
        )
        risk_points += 20

    if hostname and hostname_is_ip(
        hostname
    ):
        indicators.append(
            "URL uses an IP address instead of a domain name"
        )
        risk_points += 20

    if hostname in SHORTENER_DOMAINS:
        indicators.append(
            "URL uses a shortening service"
        )
        risk_points += 12

    if "@" in decoded_url:
        indicators.append(
            "URL contains an @ character"
        )
        risk_points += 15

    if len(decoded_url) > MAX_REASONABLE_URL_LENGTH:
        indicators.append(
            "URL is unusually long"
        )
        risk_points += 8

    if (
        len(hostname)
        > MAX_REASONABLE_HOSTNAME_LENGTH
    ):
        indicators.append(
            "Hostname is unusually long"
        )
        risk_points += 7

    subdomain_count = count_subdomains(
        hostname
    )

    if (
        subdomain_count
        > MAX_REASONABLE_SUBDOMAINS
    ):
        indicators.append(
            "Domain contains an excessive number of subdomains"
        )
        risk_points += 10

    matched_tld = next(
        (
            tld
            for tld in HIGHER_RISK_TLDS
            if hostname.endswith(tld)
        ),
        None
    )

    if matched_tld:
        indicators.append(
            f"Domain uses a higher-risk TLD: {matched_tld}"
        )
        risk_points += 8

    if hostname.startswith(
        "xn--"
    ) or ".xn--" in hostname:
        indicators.append(
            "Domain uses Punycode and may require homograph inspection"
        )
        risk_points += 15

    if contains_non_ascii(
        hostname
    ):
        indicators.append(
            "Hostname contains non-ASCII characters"
        )
        risk_points += 12

    phishing_keywords = find_keywords(
        decoded_url,
        PHISHING_KEYWORDS
    )

    if phishing_keywords:
        indicators.append(
            "URL contains phishing-related keyword(s): "
            + ", ".join(phishing_keywords)
        )
        risk_points += min(
            15,
            len(phishing_keywords) * 3
        )

    brand_terms = find_keywords(
        decoded_url,
        BRAND_TERMS
    )

    if brand_terms:
        indicators.append(
            "URL references brand name(s): "
            + ", ".join(brand_terms)
        )
        risk_points += min(
            8,
            len(brand_terms) * 2
        )

    if hostname.count("-") >= 3:
        indicators.append(
            "Hostname contains many hyphens"
        )
        risk_points += 7

    if decoded_url.count("%") >= 4:
        indicators.append(
            "URL contains extensive percent encoding"
        )
        risk_points += 8

    entropy_target = (
        parsed.path
        + parsed.query
    )

    entropy = calculate_shannon_entropy(
        entropy_target
    )

    if (
        len(entropy_target) >= 25
        and entropy >= HIGH_ENTROPY_THRESHOLD
    ):
        indicators.append(
            "URL path or query contains high-entropy text"
        )
        risk_points += 8

    if parsed.port not in {
        None,
        80,
        443
    }:
        indicators.append(
            f"URL uses an uncommon explicit port: {parsed.port}"
        )
        risk_points += 7

    risk_points = min(
        risk_points,
        100
    )

    if risk_points >= 35:
        risk_level = "High"
    elif risk_points >= 12:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "url": url,
        "decoded_url": decoded_url,
        "hostname": hostname,
        "scheme": parsed.scheme,
        "port": parsed.port,
        "path": parsed.path,
        "query": parsed.query,
        "subdomain_count": subdomain_count,
        "entropy": entropy,
        "matched_keywords": phishing_keywords,
        "matched_brands": brand_terms,
        "suspicious": risk_points >= 12,
        "risk_level": risk_level,
        "risk_score": risk_points,
        "indicators": indicators
    }


def analyse_urls(
    text: str
) -> list[dict[str, Any]]:
    """
    Extract and analyse every URL found in the supplied text.
    """
    return [
        analyse_url(url)
        for url in extract_urls(text)
    ]
