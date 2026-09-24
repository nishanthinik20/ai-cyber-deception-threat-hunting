def calculate_risk(ai_prediction, severity, ioc_count=0, threat_count=0):
    """
    Calculate a risk score based on AI prediction,
    event severity, IOC count and threat-hunting findings.
    """

    score = 0

    # AI prediction
    if ai_prediction == "NORMAL":
        score += 0

    elif ai_prediction == "SUSPICIOUS":
        score += 30

    elif ai_prediction == "MALICIOUS":
        score += 50

    # Event severity
    if severity == "LOW":
        score += 5

    elif severity == "MEDIUM":
        score += 15

    elif severity == "HIGH":
        score += 25

    elif severity == "CRITICAL":
        score += 40

    # IOC contribution
    score += min(ioc_count * 10, 20)

    # Threat hunting contribution
    score += min(threat_count * 10, 20)

    # Maximum score
    score = min(score, 100)

    # Risk level
    if score >= 80:
        risk_level = "CRITICAL"

    elif score >= 60:
        risk_level = "HIGH"

    elif score >= 30:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return {
        "score": score,
        "risk_level": risk_level
    }


if __name__ == "__main__":

    print("=" * 50)
    print(" RISK ENGINE TEST")
    print("=" * 50)

    result = calculate_risk(
        ai_prediction="MALICIOUS",
        severity="HIGH",
        ioc_count=1,
        threat_count=1
    )

    print("Risk Score:", result["score"])
    print("Risk Level:", result["risk_level"])

    print("=" * 50)