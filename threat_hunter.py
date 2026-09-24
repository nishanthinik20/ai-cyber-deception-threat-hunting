from database import get_recent_events


def hunt_threats():
    """
    Analyze recent security events and identify
    possible attack patterns.
    """

    events = get_recent_events(50)

    findings = []

    if not events:
        return findings

    high_count = 0
    critical_count = 0
    deception_count = 0

    for event in events:

        event_type = event[2]
        severity = event[5]

        if severity == "HIGH":
            high_count += 1

        if severity == "CRITICAL":
            critical_count += 1

        if event_type == "DECEPTION_TRIGGER":
            deception_count += 1

    # Pattern 1: repeated high-severity events
    if high_count >= 3:
        findings.append({
            "type": "REPEATED_HIGH_ACTIVITY",
            "severity": "HIGH",
            "description": (
                "Multiple high-severity security events "
                "were detected."
            )
        })

    # Pattern 2: critical activity
    if critical_count >= 1:
        findings.append({
            "type": "CRITICAL_ACTIVITY",
            "severity": "CRITICAL",
            "description": (
                "A critical security event was detected "
                "during threat hunting."
            )
        })

    # Pattern 3: repeated deception triggers
    if deception_count >= 3:
        findings.append({
            "type": "DECEPTION_PATTERN",
            "severity": "HIGH",
            "description": (
                "Repeated access to controlled deception "
                "resources was detected."
            )
        })

    return findings


if __name__ == "__main__":

    print("=" * 50)
    print(" THREAT HUNTING ENGINE")
    print("=" * 50)

    findings = hunt_threats()

    if findings:

        for finding in findings:
            print()
            print("Threat:", finding["type"])
            print("Severity:", finding["severity"])
            print("Details:", finding["description"])

    else:
        print()
        print("No correlated threats detected.")

    print("=" * 50)