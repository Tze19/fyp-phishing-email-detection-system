from pathlib import Path
from typing import Any
import hashlib
import io
import re
import zipfile

import magic
from pypdf import PdfReader


# Extensions that may directly execute code or install software.
DANGEROUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".ps1",
    ".psm1",
    ".jar",
    ".msi",
    ".msp",
    ".hta",
    ".cpl",
    ".reg",
    ".lnk",
    ".iso"
}


# Office formats that may contain VBA macros.
MACRO_ENABLED_EXTENSIONS = {
    ".docm",
    ".dotm",
    ".xlsm",
    ".xltm",
    ".xlam",
    ".pptm",
    ".potm",
    ".ppsm",
    ".sldm"
}


# Archive files are not automatically malicious, but their contents
# require additional inspection.
ARCHIVE_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".bz2",
    ".xz"
}


# Common document/image extensions attackers place before an executable
# extension to disguise the real file type.
DECOY_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".txt",
    ".rtf",
    ".csv"
}


SUSPICIOUS_FILENAME_TERMS = {
    "invoice",
    "payment",
    "receipt",
    "salary",
    "payroll",
    "bank",
    "statement",
    "account",
    "verify",
    "verification",
    "password",
    "urgent",
    "order",
    "refund",
    "resume",
    "cv",
    "quotation",
    "purchase",
    "delivery"
}


MAX_PDF_PAGES = 10
MAX_PDF_TEXT_LENGTH = 5_000
MAX_ARCHIVE_ENTRIES = 100


def calculate_sha256(payload: bytes) -> str:
    """
    Calculate the SHA-256 digest of the attachment.
    """
    return hashlib.sha256(payload).hexdigest()


def detect_double_extension(filename: str) -> bool:
    """
    Detect filenames such as invoice.pdf.exe or image.jpg.scr.
    """
    suffixes = [
        suffix.lower()
        for suffix in Path(filename).suffixes
    ]

    if len(suffixes) < 2:
        return False

    final_extension = suffixes[-1]
    previous_extension = suffixes[-2]

    return (
        previous_extension in DECOY_EXTENSIONS
        and (
            final_extension in DANGEROUS_EXTENSIONS
            or final_extension in MACRO_ENABLED_EXTENSIONS
        )
    )


def detect_suspicious_multiple_extension(
    filename: str
) -> bool:
    """
    Detect a dangerous or macro-enabled extension appearing
    before the final filename extension.

    This identifies unusual names such as report.exe.pdf,
    while distinguishing them from the more dangerous
    report.pdf.exe pattern.
    """
    suffixes = [
        suffix.lower()
        for suffix in Path(filename).suffixes
    ]

    if len(suffixes) < 2:
        return False

    earlier_extensions = suffixes[:-1]

    return any(
        extension in DANGEROUS_EXTENSIONS
        or extension in MACRO_ENABLED_EXTENSIONS
        for extension in earlier_extensions
    )


def contains_suspicious_filename_term(
    filename: str
) -> list[str]:
    """
    Return suspicious social-engineering terms found in the filename.
    """
    normalised_name = re.sub(
        r"[^a-z0-9]+",
        " ",
        filename.lower()
    )

    found_terms = sorted(
        term
        for term in SUSPICIOUS_FILENAME_TERMS
        if re.search(
            rf"\b{re.escape(term)}\b",
            normalised_name
        )
    )

    return found_terms


def inspect_zip_archive(
    payload: bytes
) -> dict[str, Any]:
    """
    Statically inspect ZIP metadata without extracting files.

    The function identifies:
    - invalid ZIP files;
    - encrypted entries;
    - nested archives;
    - dangerous extensions inside the archive;
    - unusually large entry counts.
    """
    result = {
        "valid_zip": False,
        "encrypted": False,
        "entry_count": 0,
        "dangerous_entries": [],
        "nested_archives": [],
        "inspection_error": None
    }

    try:
        with zipfile.ZipFile(
            io.BytesIO(payload)
        ) as archive:
            result["valid_zip"] = True

            entries = archive.infolist()
            result["entry_count"] = len(entries)

            for entry in entries[:MAX_ARCHIVE_ENTRIES]:
                entry_name = entry.filename
                entry_extension = (
                    Path(entry_name)
                    .suffix
                    .lower()
                )

                # Bit 0 indicates traditional ZIP encryption.
                if entry.flag_bits & 0x1:
                    result["encrypted"] = True

                if (
                    entry_extension in DANGEROUS_EXTENSIONS
                    or entry_extension
                    in MACRO_ENABLED_EXTENSIONS
                ):
                    result["dangerous_entries"].append(
                        entry_name
                    )

                if entry_extension in ARCHIVE_EXTENSIONS:
                    result["nested_archives"].append(
                        entry_name
                    )

    except zipfile.BadZipFile:
        result["inspection_error"] = (
            "The attachment has a .zip extension "
            "but is not a valid ZIP archive."
        )

    except Exception as exc:
        result["inspection_error"] = (
            f"ZIP inspection failed: {exc}"
        )

    return result


def extract_pdf_text(payload: bytes) -> dict[str, Any]:
    """
    Extract text from the first pages of a PDF.

    pypdf performs text extraction but does not OCR image-only PDFs.
    """
    result = {
        "text": "",
        "encrypted": False,
        "page_count": 0,
        "extraction_error": None
    }

    try:
        reader = PdfReader(
            io.BytesIO(payload)
        )

        result["page_count"] = len(reader.pages)
        result["encrypted"] = bool(reader.is_encrypted)

        if reader.is_encrypted:
            try:
                decrypt_result = reader.decrypt("")
            except Exception:
                decrypt_result = 0

            if decrypt_result == 0:
                result["extraction_error"] = (
                    "PDF is encrypted or password protected."
                )
                return result

        text_parts: list[str] = []

        for page in reader.pages[:MAX_PDF_PAGES]:
            extracted_text = page.extract_text() or ""
            text_parts.append(extracted_text)

        result["text"] = (
            "\n".join(text_parts)
            [:MAX_PDF_TEXT_LENGTH]
        )

    except Exception as exc:
        result["extraction_error"] = (
            f"PDF text extraction failed: {exc}"
        )

    return result


def determine_mime_mismatch(
    extension: str,
    detected_type: str
) -> bool:
    """
    Check selected extension-to-MIME combinations.

    This is intentionally conservative to reduce false positives.
    """
    expected_mime_types = {
        ".pdf": {"application/pdf"},
        ".zip": {
            "application/zip",
            "application/x-zip-compressed"
        },
        ".png": {"image/png"},
        ".jpg": {"image/jpeg"},
        ".jpeg": {"image/jpeg"},
        ".gif": {"image/gif"},
        ".txt": {
            "text/plain",
            "application/octet-stream"
        }
    }

    expected = expected_mime_types.get(extension)

    if not expected:
        return False

    return detected_type not in expected


def analyse_attachment(
    attachment: dict[str, Any]
) -> dict[str, Any]:
    """
    Perform static analysis of one attachment.

    The attachment dictionary is expected to contain:
    filename, content_type, size_bytes and payload.
    """
    filename = str(
        attachment.get(
            "filename",
            "Unnamed attachment"
        )
    )

    payload = attachment.get(
        "payload",
        b""
    ) or b""

    reported_content_type = str(
        attachment.get(
            "content_type",
            "application/octet-stream"
        )
    )

    size_bytes = int(
        attachment.get(
            "size_bytes",
            len(payload)
        )
    )

    extension = (
        Path(filename)
        .suffix
        .lower()
    )

    suffixes = [
        suffix.lower()
        for suffix in Path(filename).suffixes
    ]

    detected_type = (
        magic.from_buffer(
            payload,
            mime=True
        )
        if payload
        else "unknown"
    )

    indicators: list[str] = []
    severity_points = 0

    if extension in DANGEROUS_EXTENSIONS:
        indicators.append(
            f"Dangerous attachment extension detected: "
            f"{extension}"
        )
        severity_points += 30

    if extension in MACRO_ENABLED_EXTENSIONS:
        indicators.append(
            "Macro-enabled Microsoft Office attachment detected"
        )
        severity_points += 20

    if detect_double_extension(filename):
        indicators.append(
            "Double extension may disguise the real file type"
        )
        severity_points += 25

    elif detect_suspicious_multiple_extension(filename):
        indicators.append(
            "Filename contains a dangerous or macro-enabled "
            "extension before the final extension"
        )
        severity_points += 12

    suspicious_terms = (
        contains_suspicious_filename_term(
            filename
        )
    )

    if suspicious_terms:
        indicators.append(
            "Filename contains social-engineering term(s): "
            + ", ".join(suspicious_terms)
        )
        severity_points += min(
            10,
            len(suspicious_terms) * 2
        )

    if determine_mime_mismatch(
        extension,
        detected_type
    ):
        indicators.append(
            "Filename extension does not match "
            "the detected MIME type"
        )
        severity_points += 20

    archive_result = None

    if extension in ARCHIVE_EXTENSIONS:
        indicators.append(
            "Archive attachment requires additional inspection"
        )
        severity_points += 5

    if extension == ".zip":
        archive_result = inspect_zip_archive(
            payload
        )

        if archive_result["encrypted"]:
            indicators.append(
                "ZIP archive contains encrypted "
                "or password-protected entries"
            )
            severity_points += 15

        if archive_result["dangerous_entries"]:
            indicators.append(
                "ZIP archive contains dangerous or "
                "macro-enabled file types"
            )
            severity_points += 30

        if archive_result["nested_archives"]:
            indicators.append(
                "ZIP archive contains nested archive files"
            )
            severity_points += 8

        if archive_result["entry_count"] > MAX_ARCHIVE_ENTRIES:
            indicators.append(
                "ZIP archive contains an unusually "
                "large number of entries"
            )
            severity_points += 5

        if archive_result["inspection_error"]:
            indicators.append(
                archive_result["inspection_error"]
            )
            severity_points += 10

    pdf_result = None
    pdf_text_preview = ""

    if detected_type == "application/pdf":
        pdf_result = extract_pdf_text(
            payload
        )

        pdf_text_preview = (
            pdf_result["text"][:1_000]
        )

        if pdf_result["encrypted"]:
            indicators.append(
                "PDF is encrypted or password protected"
            )
            severity_points += 12

        if pdf_result["extraction_error"]:
            indicators.append(
                pdf_result["extraction_error"]
            )

        if (
            not pdf_result["text"].strip()
            and not pdf_result["encrypted"]
        ):
            indicators.append(
                "No extractable PDF text was found; "
                "the PDF may contain only images"
            )
            severity_points += 3

    sha256 = calculate_sha256(
        payload
    )

    severity_points = min(
        severity_points,
        100
    )

    if severity_points >= 30:
        attachment_risk = "High"
    elif severity_points >= 10:
        attachment_risk = "Medium"
    else:
        attachment_risk = "Low"

    return {
        "filename": filename,
        "extension": extension,
        "all_extensions": suffixes,
        "reported_content_type": reported_content_type,
        "detected_content_type": detected_type,
        "size_bytes": size_bytes,
        "sha256": sha256,
        "suspicious": severity_points >= 10,
        "risk_level": attachment_risk,
        "risk_score": severity_points,
        "indicators": indicators,
        "pdf_text_preview": pdf_text_preview,
        "pdf_details": pdf_result,
        "archive_details": archive_result
    }


def analyse_attachments(
    attachments: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """
    Analyse all attachments extracted from an email.
    """
    return [
        analyse_attachment(attachment)
        for attachment in attachments
    ]
