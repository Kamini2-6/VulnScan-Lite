import requests


SECURITY_HEADERS = {
    "Content-Security-Policy": 10,
    "X-Frame-Options": 10,
    "Strict-Transport-Security": 10,
}

REMEDIATIONS = {
    "Content-Security-Policy": {
        "severity": "HIGH",
        "how_to_fix": (
            "Configure a suitable Content-Security-Policy header "
            "at the web server or application level. Start with "
            "a restrictive policy and test it before enforcing it."
        )
    },

    "X-Frame-Options": {
        "severity": "MEDIUM",
        "how_to_fix": (
            "Configure X-Frame-Options to control whether the "
            "website can be embedded in frames. Alternatively, "
            "use an appropriate CSP frame-ancestors policy."
        )
    },

    "Strict-Transport-Security": {
        "severity": "HIGH",
        "how_to_fix": (
            "Enable Strict-Transport-Security after confirming "
            "that the website is fully accessible over HTTPS. "
            "Configure an appropriate max-age value."
        )
    }
}


def check_headers(url: str):
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "VulnScan-Lite/1.0"
            }
        )

        headers = response.headers

        found_headers = {}
        passed_checks = []
        failed_checks = []
        score = 0

        for header, points in SECURITY_HEADERS.items():
            if header in headers:
                found_headers[header] = {
                    "status": "Present",
                    "value": headers.get(header),
                    "score": points,
                    "severity": "PASS"
                }
                score += points

                passed_checks.append({
                    "check": header,
                    "status": "Passed",
                    "score": points
                })
            else:
                found_headers[header] = {
                    "status": "Missing",
                    "value": None,
                    "score": -points,
                     "severity": REMEDIATIONS[
                        header
                    ]["severity"],
                    "how_to_fix": REMEDIATIONS[
                        header
                    ]["how_to_fix"]
                }

                score -= points

                failed_checks.append({
                    "check": header,
                    "status": "Failed",
                    "score": -points,
                    "severity": REMEDIATIONS[
                        header
                    ]["severity"],
                    "how_to_fix": REMEDIATIONS[
                        header
                    ]["how_to_fix"]
                })

        return {
            "headers": found_headers,
            "score": score,
            "passed_checks": passed_checks,
            "failed_checks": failed_checks,
            "status_code": response.status_code,
            "final_url": response.url,
            "error": None
        }

    except requests.exceptions.RequestException as e:
        return {
            "headers": {},
            "score": 0,
            "passed_checks": [],
            "failed_checks": [],
            "status_code": None,
            "final_url": url,
            "error": str(e)
        }