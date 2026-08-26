from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse
import ipaddress
import socket
import time
import uuid

from selenium import webdriver
from selenium.common.exceptions import (
    InvalidSessionIdException,
    TimeoutException,
    WebDriverException,
)
from selenium.webdriver.chromium.options import ChromiumOptions


DEFAULT_REMOTE_URL = "http://127.0.0.1:4444/wd/hub"

MAX_SANDBOX_URLS = 3
PAGE_LOAD_TIMEOUT_SECONDS = 20
SCRIPT_TIMEOUT_SECONDS = 10
OBSERVATION_SECONDS = 5
MAX_PAGE_SOURCE_LENGTH = 500_000


CAPTCHA_TERMS = {
    "captcha",
    "recaptcha",
    "hcaptcha",
    "verify you are human",
    "human verification",
    "i am not a robot",
    "security check",
}


def cleanup_old_screenshots(
    screenshot_directory: Path,
    maximum_age_hours: int = 24,
) -> int:
    """
    Delete sandbox screenshots older than the specified age.
    """
    if not screenshot_directory.exists():
        return 0

    current_time = time.time()
    maximum_age_seconds = maximum_age_hours * 3600
    deleted_count = 0

    for screenshot_path in screenshot_directory.glob("*.png"):
        try:
            file_age = (
                current_time
                - screenshot_path.stat().st_mtime
            )

            if file_age > maximum_age_seconds:
                screenshot_path.unlink()
                deleted_count += 1

        except OSError:
            continue

    return deleted_count



def _is_disallowed_ip(ip_text: str) -> bool:
    """
    Block destinations that could expose the host, VM, local network,
    cloud metadata endpoints, or other non-public resources.
    """
    address = ipaddress.ip_address(ip_text)

    return any(
        [
            address.is_private,
            address.is_loopback,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
            address.is_unspecified,
        ]
    )


def validate_public_url(url: str) -> dict[str, Any]:
    """
    Validate a URL before passing it to the browser sandbox.

    Only HTTP and HTTPS URLs resolving exclusively to public IP
    addresses are allowed.
    """
    result: dict[str, Any] = {
        "allowed": False,
        "reason": "",
        "hostname": "",
        "resolved_ips": [],
    }

    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() not in {"http", "https"}:
            result["reason"] = "Only HTTP and HTTPS URLs are allowed."
            return result

        hostname = parsed.hostname

        if not hostname:
            result["reason"] = "The URL has no valid hostname."
            return result

        result["hostname"] = hostname.lower()

        # Explicitly block common localhost names.
        if result["hostname"] in {
            "localhost",
            "localhost.localdomain",
        }:
            result["reason"] = "Localhost destinations are blocked."
            return result

        port = parsed.port or (
            443 if parsed.scheme.lower() == "https" else 80
        )

        address_records = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )

        resolved_ips = sorted(
            {
                record[4][0]
                for record in address_records
            }
        )

        if not resolved_ips:
            result["reason"] = "The hostname did not resolve."
            return result

        result["resolved_ips"] = resolved_ips

        blocked_ips = [
            ip_value
            for ip_value in resolved_ips
            if _is_disallowed_ip(ip_value)
        ]

        if blocked_ips:
            result["reason"] = (
                "The destination resolves to a private, local, "
                "reserved, or otherwise non-public IP address."
            )
            return result

        result["allowed"] = True
        result["reason"] = "URL passed public-destination validation."
        return result

    except (ValueError, socket.gaierror, OSError) as exc:
        result["reason"] = f"URL validation failed: {exc}"
        return result


def _create_remote_driver(
    remote_url: str,
) -> webdriver.Remote:
    """
    Create a remote Chromium session inside the Selenium container.
    """
    options = ChromiumOptions()

    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--no-first-run")
    options.add_argument("--no-default-browser-check")
    options.add_argument("--disable-background-networking")
    options.add_argument("--disable-sync")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-notifications")
    options.add_argument("--disable-popup-blocking")
    options.add_argument("--window-size=1365,768")

    # Avoid automatically downloading files.
    preferences = {
        "download_restrictions": 3,
        "download.prompt_for_download": False,
        "safebrowsing.enabled": True,
        "profile.default_content_setting_values.notifications": 2,
    }

    options.add_experimental_option(
        "prefs",
        preferences,
    )

    driver = webdriver.Remote(
        command_executor=remote_url,
        options=options,
    )

    driver.set_page_load_timeout(
        PAGE_LOAD_TIMEOUT_SECONDS
    )

    driver.set_script_timeout(
        SCRIPT_TIMEOUT_SECONDS
    )

    return driver


def _different_hostname(
    original_url: str,
    final_url: str,
) -> bool:
    original_hostname = (
        urlparse(original_url).hostname or ""
    ).lower()

    final_hostname = (
        urlparse(final_url).hostname or ""
    ).lower()

    return bool(
        original_hostname
        and final_hostname
        and original_hostname != final_hostname
    )


def _detect_captcha(
    page_source: str,
    page_title: str,
) -> bool:
    searchable_text = (
        f"{page_title} "
        f"{page_source[:MAX_PAGE_SOURCE_LENGTH]}"
    ).lower()

    return any(
        term in searchable_text
        for term in CAPTCHA_TERMS
    )


def analyse_url_in_sandbox(
    url: str,
    screenshot_directory: Path,
    remote_url: str = DEFAULT_REMOTE_URL,
) -> dict[str, Any]:
    """
    Open one public URL using Chromium inside the Docker Selenium
    container and collect lightweight behavioural evidence.
    """
    validation = validate_public_url(url)

    result: dict[str, Any] = {
        "attempted": False,
        "status": "blocked",
        "original_url": url,
        "final_url": "",
        "page_title": "",
        "redirect_detected": False,
        "cross_domain_redirect": False,
        "captcha_detected": False,
        "screenshot_filename": "",
        "screenshot_url": "",
        "elapsed_seconds": 0.0,
        "resolved_ips": validation["resolved_ips"],
        "validation_reason": validation["reason"],
        "error": "",
        "indicators": [],
    }

    if not validation["allowed"]:
        result["indicators"].append(
            "Sandbox blocked a non-public or invalid destination"
        )
        return result

    screenshot_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    driver: webdriver.Remote | None = None
    start_time = time.monotonic()

    try:
        result["attempted"] = True
        result["status"] = "running"

        driver = _create_remote_driver(
            remote_url
        )

        driver.get(url)

        time.sleep(
            OBSERVATION_SECONDS
        )

        final_url = driver.current_url or ""
        page_title = driver.title or ""
        page_source = driver.page_source or ""

        redirect_detected = (
            final_url.rstrip("/")
            != url.rstrip("/")
        )

        cross_domain_redirect = _different_hostname(
            url,
            final_url,
        )

        captcha_detected = _detect_captcha(
            page_source,
            page_title,
        )

        screenshot_filename = (
            f"{uuid.uuid4().hex}.png"
        )

        screenshot_path = (
            screenshot_directory
            / screenshot_filename
        )

        screenshot_bytes = (
            driver.get_screenshot_as_png()
        )

        screenshot_path.write_bytes(
            screenshot_bytes
        )

        result.update(
            {
                "status": "success",
                "final_url": final_url,
                "page_title": page_title,
                "redirect_detected": redirect_detected,
                "cross_domain_redirect": (
                    cross_domain_redirect
                ),
                "captcha_detected": captcha_detected,
                "screenshot_filename": (
                    screenshot_filename
                ),
                "screenshot_url": (
                    f"/static/sandbox/"
                    f"{screenshot_filename}"
                ),
            }
        )

        if redirect_detected:
            result["indicators"].append(
                "Sandbox observed a URL redirect"
            )

        if cross_domain_redirect:
            result["indicators"].append(
                "Sandbox observed a redirect to a different domain"
            )

        if captcha_detected:
            result["indicators"].append(
                "CAPTCHA or human-verification content was detected"
            )

    except TimeoutException:
        result["status"] = "timeout"
        result["error"] = (
            "The page did not finish loading within "
            f"{PAGE_LOAD_TIMEOUT_SECONDS} seconds."
        )

    except WebDriverException as exc:
        result["status"] = "error"
        result["error"] = (
            f"Selenium WebDriver error: {exc}"
        )

    except OSError as exc:
        result["status"] = "error"
        result["error"] = (
            f"Screenshot or file-system error: {exc}"
        )

    finally:
        result["elapsed_seconds"] = round(
            time.monotonic() - start_time,
            3,
        )

        if driver is not None:
            try:
                driver.quit()
            except (
                InvalidSessionIdException,
                WebDriverException,
            ):
                pass

    return result


def enrich_urls_with_sandbox(
    url_results: list[dict[str, Any]],
    screenshot_directory: Path,
    remote_url: str = DEFAULT_REMOTE_URL,
    maximum_urls: int = MAX_SANDBOX_URLS,
) -> list[dict[str, Any]]:
    """
    Add a sandbox result to up to `maximum_urls` static URL results.

    The returned dictionaries keep all existing URL analyser fields,
    so they remain compatible with the current risk engine and template.
    """
    cleanup_old_screenshots(
        screenshot_directory=screenshot_directory,
        maximum_age_hours=24,
    )

    enriched_results: list[dict[str, Any]] = []

    for index, url_result in enumerate(
        url_results
    ):
        enriched = dict(
            url_result
        )

        if index >= maximum_urls:
            enriched["sandbox"] = {
                "attempted": False,
                "status": "skipped",
                "original_url": enriched.get(
                    "url",
                    "",
                ),
                "final_url": "",
                "page_title": "",
                "redirect_detected": False,
                "cross_domain_redirect": False,
                "captcha_detected": False,
                "screenshot_filename": "",
                "screenshot_url": "",
                "elapsed_seconds": 0.0,
                "resolved_ips": [],
                "validation_reason": (
                    "Skipped because the per-email "
                    "sandbox URL limit was reached."
                ),
                "error": "",
                "indicators": [],
            }

            enriched_results.append(
                enriched
            )

            continue

        sandbox_result = analyse_url_in_sandbox(
            url=enriched.get("url", ""),
            screenshot_directory=(
                screenshot_directory
            ),
            remote_url=remote_url,
        )

        enriched["sandbox"] = (
            sandbox_result
        )

        dynamic_points = 0

        if sandbox_result.get(
            "cross_domain_redirect"
        ):
            dynamic_points += 12

        elif sandbox_result.get(
            "redirect_detected"
        ):
            dynamic_points += 5

        if sandbox_result.get(
            "captcha_detected"
        ):
            dynamic_points += 5

        if (
            sandbox_result.get("status")
            == "blocked"
        ):
            dynamic_points += 20

        if dynamic_points > 0:
            enriched["risk_score"] = min(
                100,
                int(
                    enriched.get(
                        "risk_score",
                        0,
                    )
                )
                + dynamic_points,
            )

            existing_indicators = list(
                enriched.get(
                    "indicators",
                    [],
                )
            )

            existing_indicators.extend(
                sandbox_result.get(
                    "indicators",
                    [],
                )
            )

            enriched["indicators"] = (
                existing_indicators
            )

            enriched["suspicious"] = True

            if enriched["risk_score"] >= 35:
                enriched["risk_level"] = "High"
            elif enriched["risk_score"] >= 12:
                enriched["risk_level"] = "Medium"
            else:
                enriched["risk_level"] = "Low"

        enriched_results.append(
            enriched
        )

    return enriched_results
