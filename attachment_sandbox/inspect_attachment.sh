#!/usr/bin/env bash

set -u

TARGET_FILE="/input/attachment"
OUTPUT_FILE="/output/result.txt"

{
    echo "inspection_status=started"

    if [ ! -f "$TARGET_FILE" ]; then
        echo "error=Attachment file was not found"
        echo "inspection_status=failed"
        exit 1
    fi

    FILE_TYPE="$(file -b "$TARGET_FILE" | tr '\n' ' ')"
    MIME_TYPE="$(file -b --mime-type "$TARGET_FILE" | tr '\n' ' ')"

    echo "file_type=$FILE_TYPE"
    echo "mime_type=$MIME_TYPE"
    echo "size_bytes=$(stat -c%s "$TARGET_FILE")"
    echo "sha256=$(sha256sum "$TARGET_FILE" | awk '{print $1}')"

    echo "strings_preview_begin"
    strings -a -n 6 "$TARGET_FILE" 2>/dev/null | head -n 40
    echo "strings_preview_end"

    if [ "$MIME_TYPE" = "application/zip" ]; then
        echo "archive_listing_begin"
        unzip -l "$TARGET_FILE" 2>&1 | head -n 100
        echo "archive_listing_end"
    fi

    case "$MIME_TYPE" in
        application/x-7z-compressed|application/x-rar)
            echo "archive_listing_begin"
            7z l "$TARGET_FILE" 2>&1 | head -n 100
            echo "archive_listing_end"
            ;;
    esac

    if [ "$MIME_TYPE" = "application/pdf" ]; then
        echo "pdf_information_begin"
        pdfinfo "$TARGET_FILE" 2>&1 | head -n 50
        echo "pdf_information_end"

        echo "pdf_text_preview_begin"
        pdftotext "$TARGET_FILE" - 2>/dev/null | head -n 40
        echo "pdf_text_preview_end"
    fi

    echo "inspection_status=completed"

} > "$OUTPUT_FILE"
