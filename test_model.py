from pathlib import Path
import joblib


MODEL_PATH = Path("models/phishing_email_detection_pipeline.joblib")


def main() -> None:
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model not found: {MODEL_PATH.resolve()}")

    package = joblib.load(MODEL_PATH)

    pipeline = package["pipeline"]
    label_mapping = package["label_mapping"]
    max_text_length = package["max_text_length"]

    test_messages = [
        """
        Subject: Project meeting tomorrow

        Please attend the project discussion tomorrow at 10:00 AM.
        Bring your current progress notes.
        """,
        """
        Subject: Urgent account suspension

        Your account has been suspended. Verify your password immediately
        at http://fake-account-verification.example/login or your account
        will be permanently closed.
        """
    ]

    predictions = pipeline.predict(
        [message[:max_text_length] for message in test_messages]
    )

    for message, prediction in zip(test_messages, predictions):
        label = label_mapping[int(prediction)]

        print("=" * 60)
        print(message.strip()[:200])
        print(f"\nPrediction: {label}")


if __name__ == "__main__":
    main()
