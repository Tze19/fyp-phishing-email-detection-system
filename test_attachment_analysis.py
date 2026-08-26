from services.attachment_analyser import analyse_attachment


test_attachments = [
    {
        "filename": "project_report.txt",
        "content_type": "text/plain",
        "size_bytes": len(b"Final year project report"),
        "payload": b"Final year project report"
    },
    {
        "filename": "urgent_invoice.pdf.exe",
        "content_type": "application/octet-stream",
        "size_bytes": len(b"MZ fake executable test data"),
        "payload": b"MZ fake executable test data"
    },
    {
        "filename": "salary_information.xlsm",
        "content_type": (
            "application/vnd.ms-excel.sheet.macroEnabled.12"
        ),
        "size_bytes": len(b"Fake macro document test data"),
        "payload": b"Fake macro document test data"
    }
]


for attachment in test_attachments:
    result = analyse_attachment(
        attachment
    )

    print("=" * 70)
    print("Filename:", result["filename"])
    print("Detected type:", result["detected_content_type"])
    print("Risk level:", result["risk_level"])
    print("Risk score:", result["risk_score"])
    print("Suspicious:", result["suspicious"])
    print("Indicators:")

    for indicator in result["indicators"]:
        print("-", indicator)
