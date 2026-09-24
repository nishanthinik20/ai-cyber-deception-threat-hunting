from flask import Flask, render_template, jsonify

from database import init_db, get_recent_events
from ai_analyzer import analyze_event
from ioc_engine import extract_iocs
from risk_engine import calculate_risk
from threat_hunter import hunt_threats


app = Flask(__name__)

init_db()


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/api/events")
def events():

    database_events = get_recent_events(20)

    events_list = []

    for event in database_events:

        event_id = event[0]
        timestamp = event[1]
        event_type = event[2]
        source = event[3]
        description = event[4]
        severity = event[5]
        status = event[6]

        ai_result = analyze_event({
            "event_type": event_type,
            "severity": severity,
            "description": description
        })

        iocs = extract_iocs(
            f"{source} {description}"
        )

        ioc_count = (
            len(iocs["ips"]) +
            len(iocs["domains"])
        )

        threat_count = 0

        if ai_result["prediction"] in [
            "SUSPICIOUS",
            "MALICIOUS"
        ]:
            threat_count = 1

        risk = calculate_risk(
            ai_prediction=ai_result["prediction"],
            severity=severity,
            ioc_count=ioc_count,
            threat_count=threat_count
        )

        events_list.append({

            "id": event_id,

            "timestamp": timestamp,

            "event_type": event_type,

            "source": source,

            "description": description,

            "severity": severity,

            "status": status,

            "ai_prediction":
                ai_result["prediction"],

            "ai_confidence":
                ai_result["confidence"],

            "iocs":
                iocs,

            "risk_score":
                risk["score"],

            "risk_level":
                risk["risk_level"]

        })

    return jsonify(events_list)


@app.route("/api/status")
def status():

    return jsonify({

        "status": "ONLINE",

        "monitoring": True,

        "database": True

    })


@app.route("/api/stats")
def stats():

    database_events = get_recent_events(1000)

    total = len(database_events)

    high = 0

    critical = 0

    suspicious = 0

    ioc_count = 0

    for event in database_events:

        severity = event[5]

        if severity == "HIGH":
            high += 1

        elif severity == "CRITICAL":
            critical += 1

        description = event[4] or ""

        source = event[3] or ""

        iocs = extract_iocs(
            f"{source} {description}"
        )

        ioc_count += (
            len(iocs["ips"]) +
            len(iocs["domains"])
        )

        if severity in [
            "HIGH",
            "CRITICAL"
        ]:
            suspicious += 1

    return jsonify({

        "total_events": total,

        "active_incidents":
            high + critical,

        "suspicious_events":
            suspicious,

        "iocs":
            ioc_count

    })


@app.route("/api/threats")
def threats():

    findings = hunt_threats()

    database_events = get_recent_events(50)

    high_risk = 0

    for event in database_events:

        severity = event[5]

        if severity in [
            "HIGH",
            "CRITICAL"
        ]:
            high_risk += 1

    return jsonify({

        "count":
            len(findings),

        "events_analyzed":
            len(database_events),

        "high_risk_events":
            high_risk,

        "findings":
            findings

    })


@app.route("/api/incidents")
def incidents():

    database_events = get_recent_events(50)

    incident_list = []

    for event in database_events:

        event_id = event[0]
        timestamp = event[1]
        event_type = event[2]
        source = event[3]
        description = event[4]
        severity = event[5]
        status = event[6]

        ai_result = analyze_event({

            "event_type":
                event_type,

            "severity":
                severity,

            "description":
                description

        })

        iocs = extract_iocs(
            f"{source} {description}"
        )

        ioc_count = (
            len(iocs["ips"]) +
            len(iocs["domains"])
        )

        threat_count = 0

        if ai_result["prediction"] in [
            "SUSPICIOUS",
            "MALICIOUS"
        ]:
            threat_count = 1

        risk = calculate_risk(

            ai_prediction=
                ai_result["prediction"],

            severity=
                severity,

            ioc_count=
                ioc_count,

            threat_count=
                threat_count

        )

        if risk["risk_level"] in [
            "HIGH",
            "CRITICAL"
        ]:

            incident_list.append({

                "incident_id":
                    f"INC-{event_id:04d}",

                "timestamp":
                    timestamp,

                "event_type":
                    event_type,

                "source":
                    source,

                "description":
                    description,

                "severity":
                    severity,

                "status":
                    status,

                "ai_prediction":
                    ai_result["prediction"],

                "ai_confidence":
                    ai_result["confidence"],

                "risk_score":
                    risk["score"],

                "risk_level":
                    risk["risk_level"],

                "iocs":
                    iocs

            })

    return jsonify(incident_list)


if __name__ == "__main__":

    print("=" * 55)

    print(
        " CYBER DEFENSE COMMAND CENTER"
    )

    print("=" * 55)

    print(
        " Live Dashboard: "
        "http://127.0.0.1:5000"
    )

    print(
        " Monitoring Status: ONLINE"
    )

    print("=" * 55)

    app.run(

        host="127.0.0.1",

        port=5000,

        debug=True

    )