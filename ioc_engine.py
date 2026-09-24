import re


def extract_iocs(text):

    if not text:
        return {
            "ips": [],
            "domains": []
        }

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    domain_pattern = (
        r"\b(?:[a-zA-Z0-9-]+\.)+"
        r"(?:com|net|org|in|io|xyz)\b"
    )

    all_ips = re.findall(
        ip_pattern,
        text
    )

    all_domains = re.findall(
        domain_pattern,
        text
    )

    # Ignore local/private test addresses
    ignored_ips = {
        "127.0.0.1",
        "0.0.0.0"
    }

    ips = [
        ip for ip in set(all_ips)
        if ip not in ignored_ips
    ]

    domains = list(
        set(all_domains)
    )

    return {
        "ips": ips,
        "domains": domains
    }


if __name__ == "__main__":

    test_text = (
        "Suspicious connection detected from "
        "192.168.1.25 to suspicious-example.com"
    )

    result = extract_iocs(test_text)

    print("IOC Detection Test")
    print("-" * 30)

    print(
        "IP Addresses:",
        result["ips"]
    )

    print(
        "Domains:",
        result["domains"]
    )