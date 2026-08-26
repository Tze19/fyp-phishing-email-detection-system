from html import unescape
from pathlib import Path
from typing import Any
import re

import joblib


class MLAnalyser:
    def __init__(self, model_path: Path) -> None:
        if not model_path.exists():
            raise FileNotFoundError(
                f"Model was not found: {model_path}"
            )

        self.package: dict[str, Any] = joblib.load(model_path)
        self.pipeline = self.package["pipeline"]
        self.label_mapping = self.package["label_mapping"]
        self.max_text_length = int(
            self.package["max_text_length"]
        )
        self.model_name = str(
            self.package["model_name"]
        )

    def clean_text(self, text: str) -> str:
        if not isinstance(text, str):
            return ""

        text = unescape(text).lower()

        text = re.sub(
            r"<script.*?>.*?</script>",
            " ",
            text,
            flags=re.DOTALL | re.IGNORECASE
        )

        text = re.sub(
            r"<style.*?>.*?</style>",
            " ",
            text,
            flags=re.DOTALL | re.IGNORECASE
        )

        text = re.sub(r"<[^>]+>", " ", text)
        text = text.replace("\x00", " ")
        text = re.sub(r"\s+", " ", text).strip()

        return text[:self.max_text_length]

    def analyse(
        self,
        sender: str,
        recipient: str,
        subject: str,
        body: str
    ) -> dict[str, Any]:
        combined_text = " ".join([
            sender,
            recipient,
            subject,
            body
        ])

        clean_text = self.clean_text(combined_text)

        if len(clean_text) < 10:
            raise ValueError(
                "Email contains insufficient readable text."
            )

        prediction = int(
            self.pipeline.predict([clean_text])[0]
        )

        decision_score = None

        if hasattr(self.pipeline, "decision_function"):
            decision_score = float(
                self.pipeline.decision_function(
                    [clean_text]
                )[0]
            )

        return {
            "classification": self.label_mapping[prediction],
            "numeric_label": prediction,
            "decision_score": decision_score,
            "model_name": self.model_name
        }
