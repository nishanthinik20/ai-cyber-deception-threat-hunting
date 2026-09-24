from database import init_db, add_event
from datetime import datetime


def generate_test_event():
    add_event(
        event_type="DECEPTION_TRIGGER",
        source="127.0.0.1",
        description="Controlled decoy resource was accessed",
        severity="HIGH"
    )

    print(
        f"[{datetime.now().strftime('%H:%M:%S')}] "
        "Deception event recorded successfully."
    )


if __name__ == "__main__":
    init_db()

    print("Cyber Deception Test Module")
    print("-" * 40)

    generate_test_event()