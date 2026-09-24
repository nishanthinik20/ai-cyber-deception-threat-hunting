import os
import joblib

MODEL_PATH = os.path.join("model", "threat_model.pkl")


def analyze_event(event):
    """
    Analyze a security event using the trained AI model.
    """

    if not os.path.exists(MODEL_PATH):
        return {
            "prediction": "UNKNOWN",
            "confidence": 0,
            "message": "AI model is not trained yet."
        }

    model = joblib.load(MODEL_PATH)

    event_type = event.get("event_type", "")
    severity = event.get("severity", "")

    # Convert event information into simple numerical features
    features = [[
        1 if event_type == "DECEPTION_TRIGGER" else 0,
        1 if severity == "HIGH" else 0,
        1 if severity == "CRITICAL" else 0
    ]]

    prediction = model.predict(features)[0]

    confidence = 0

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(features)[0]
        confidence = round(max(probabilities) * 100, 2)

    return {
        "prediction": str(prediction),
        "confidence": confidence,
        "message": "AI analysis completed successfully."
    }