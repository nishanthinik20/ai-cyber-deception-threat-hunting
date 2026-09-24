let startTime = Date.now();

async function loadDashboard() {
    try {
        const response = await fetch("/api/events");
        const events = await response.json();

        updateAlerts(events);
        updateStats(events);
        updateIOCIntelligence(events);

    } catch (error) {
        console.error("Dashboard connection error:", error);
    }
}


function updateAlerts(events) {

    const container =
        document.getElementById("alerts-container");

    if (!container) return;

    container.innerHTML = "";

    if (events.length === 0) {

        container.innerHTML = `
            <div class="loading">
                No security events detected.
                Monitoring system is active.
            </div>
        `;

        return;
    }

    events.forEach(event => {

        const alert =
            document.createElement("div");

        alert.className = "alert-item";

        alert.innerHTML = `
            <div class="alert-content">

                <strong>
                    ${event.event_type}
                </strong>

                <p>
                    ${event.description}
                </p>

                <small>
                    Time: ${event.timestamp}
                    |
                    Source: ${event.source}
                    |
                    AI: ${event.ai_prediction}
                    |
                    Confidence:
                    ${event.ai_confidence}%
                </small>

            </div>

            <div class="alert-risk">

                <span>
                    ${event.risk_level}
                </span>

                <small>
                    Risk Score:
                    ${event.risk_score}
                </small>

            </div>
        `;

        container.appendChild(alert);
    });
}


function updateStats(events) {

    const total =
        document.getElementById("total-events");

    const incidents =
        document.getElementById("active-incidents");

    const iocs =
        document.getElementById("ioc-count");


    if (total) {
        total.textContent = events.length;
    }


    if (incidents) {

        const active =
            events.filter(event =>
                event.risk_level === "HIGH" ||
                event.risk_level === "CRITICAL"
            ).length;

        incidents.textContent = active;
    }


    if (iocs) {

        let count = 0;

        events.forEach(event => {

            if (event.iocs) {

                count +=
                    event.iocs.ips.length;

                count +=
                    event.iocs.domains.length;
            }
        });

        iocs.textContent = count;
    }
}


function updateIOCIntelligence(events) {

    const ipList =
        document.getElementById("ip-list");

    const domainList =
        document.getElementById("domain-list");

    if (!ipList || !domainList) return;


    let ips = [];
    let domains = [];


    events.forEach(event => {

        if (event.iocs) {

            ips.push(
                ...event.iocs.ips
            );

            domains.push(
                ...event.iocs.domains
            );
        }
    });


    ips = [...new Set(ips)];

    domains = [...new Set(domains)];


    if (ips.length > 0) {

        ipList.innerHTML =
            ips.map(ip =>
                `<span class="ioc-tag">${ip}</span>`
            ).join("");

    } else {

        ipList.textContent =
            "No IP indicators detected";
    }


    if (domains.length > 0) {

        domainList.innerHTML =
            domains.map(domain =>
                `<span class="ioc-tag">${domain}</span>`
            ).join("");

    } else {

        domainList.textContent =
            "No domain indicators detected";
    }
}


async function loadIncidents() {

    try {

        const response =
            await fetch("/api/incidents");

        const incidents =
            await response.json();

        const container =
            document.getElementById(
                "incidents-container"
            );

        if (!container) return;

        container.innerHTML = "";


        if (incidents.length === 0) {

            container.innerHTML = `
                <div class="loading">
                    No active incidents detected.
                </div>
            `;

            return;
        }


        incidents.forEach(incident => {

            const item =
                document.createElement("div");

            item.className =
                "incident-item";


            const ips =
                incident.iocs.ips.length > 0
                    ? incident.iocs.ips.join(", ")
                    : "None";


            const domains =
                incident.iocs.domains.length > 0
                    ? incident.iocs.domains.join(", ")
                    : "None";


            item.innerHTML = `

                <div class="incident-top">

                    <strong>
                        ${incident.incident_id}
                    </strong>

                    <span class="incident-risk">
                        ${incident.risk_level}
                    </span>

                </div>


                <div class="incident-details">

                    <p>
                        <b>Event:</b>
                        ${incident.event_type}
                    </p>

                    <p>
                        <b>Source:</b>
                        ${incident.source}
                    </p>

                    <p>
                        <b>AI:</b>
                        ${incident.ai_prediction}
                        (${incident.ai_confidence}%)
                    </p>

                    <p>
                        <b>Risk Score:</b>
                        ${incident.risk_score}/100
                    </p>

                    <p>
                        <b>IP IOCs:</b>
                        ${ips}
                    </p>

                    <p>
                        <b>Domain IOCs:</b>
                        ${domains}
                    </p>

                </div>
            `;

            container.appendChild(item);
        });

    } catch (error) {

        console.error(
            "Incident loading error:",
            error
        );
    }
}


async function loadThreatHunting() {

    try {

        const response =
            await fetch("/api/threats");

        const data =
            await response.json();


        const findings =
            document.getElementById(
                "hunt-findings"
            );

        const events =
            document.getElementById(
                "hunt-events"
            );

        const high =
            document.getElementById(
                "hunt-high"
            );


        if (findings) {

            findings.textContent =
                data.count;
        }


        if (events) {

            events.textContent =
                data.events_analyzed;
        }


        if (high) {

            high.textContent =
                data.high_risk_events;
        }


    } catch (error) {

        console.error(
            "Threat hunting error:",
            error
        );
    }
}


function updateUptime() {

    const uptime =
        document.getElementById("uptime");

    if (!uptime) return;


    const elapsed =
        Math.floor(
            (Date.now() - startTime) / 1000
        );


    const hours =
        Math.floor(elapsed / 3600);


    const minutes =
        Math.floor(
            (elapsed % 3600) / 60
        );


    const seconds =
        elapsed % 60;


    uptime.textContent =
        String(hours).padStart(2, "0") +
        ":" +
        String(minutes).padStart(2, "0") +
        ":" +
        String(seconds).padStart(2, "0");
}


loadDashboard();

setInterval(
    loadDashboard,
    3000
);


loadIncidents();

setInterval(
    loadIncidents,
    3000
);


loadThreatHunting();

setInterval(
    loadThreatHunting,
    3000
);


setInterval(
    updateUptime,
    1000
);


updateUptime();


const navLinks =
    document.querySelectorAll("nav a");


navLinks.forEach(link => {

    link.addEventListener(
        "click",
        function () {

            navLinks.forEach(item => {

                item.classList.remove(
                    "active"
                );

            });

            this.classList.add(
                "active"
            );
        }
    );
});