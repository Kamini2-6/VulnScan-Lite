import ssl
import socket
from datetime import datetime


def check_ssl(url: str):

    try:

        # -----------------------------------------
        # Extract hostname
        # -----------------------------------------

        hostname = (
            url
            .replace("https://", "")
            .replace("http://", "")
        )

        hostname = (
            hostname
            .split("/")[0]
            .split(":")[0]
        )

        # -----------------------------------------
        # Create secure SSL context
        # -----------------------------------------

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, 443),
            timeout=10
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as ssock:

                certificate = ssock.getpeercert()

                # Cipher information
                cipher_info = ssock.cipher()

                # TLS version
                tls_version = ssock.version()

        # -----------------------------------------
        # Certificate expiration
        # -----------------------------------------

        not_after = certificate.get(
            "notAfter"
        )

        expiry_date = None
        days_remaining = None

        if not_after:

            expiry_date = datetime.strptime(
                not_after,
                "%b %d %H:%M:%S %Y %Z"
            )

            days_remaining = (
                expiry_date -
                datetime.utcnow()
            ).days

        # -----------------------------------------
        # Cipher information
        # -----------------------------------------

        cipher_name = None
        cipher_protocol = None
        cipher_bits = None

        if cipher_info:

            cipher_name = cipher_info[0]
            cipher_protocol = cipher_info[1]
            cipher_bits = cipher_info[2]

        # -----------------------------------------
        # Checks
        # -----------------------------------------

        passed_checks = []
        failed_checks = []

        score = 0

        # -----------------------------------------
        # Certificate validity
        # -----------------------------------------

        if certificate:

            passed_checks.append({
                "check": "SSL Certificate",
                "status": "Passed",
                "score": 10
            })

            score += 10

        else:

            failed_checks.append({
                "check": "SSL Certificate",
                "status": "Failed",
                "score": -10,
                "severity": "HIGH",
                "how_to_fix": (
                    "Install a valid SSL/TLS certificate "
                    "issued by a trusted Certificate Authority "
                    "and configure it for the website hostname."
                )
            })

            score -= 10

        # -----------------------------------------
        # Certificate expiration
        # -----------------------------------------

        if days_remaining is not None:

            if days_remaining >= 0:

                passed_checks.append({
                    "check": "Certificate Expiration",
                    "status": "Passed",
                    "score": 10
                })

                score += 10

            else:

                failed_checks.append({
                    "check": "Certificate Expiration",
                    "status": "Failed",
                    "score": -10,
                    "severity": "HIGH",
                    "how_to_fix": (
                        "Renew the expired SSL/TLS certificate "
                        "and configure the renewed certificate "
                        "on the web server."
                    )
                })

                score -= 10

        else:

            failed_checks.append({
                "check": "Certificate Expiration",
                "status": "Failed",
                "score": -10,
                "severity": "HIGH",
                "how_to_fix": (
                    "Configure a valid SSL/TLS certificate "
                    "with a readable expiration date."
                )
            })

            score -= 10

        # -----------------------------------------
        # Cipher strength
        # -----------------------------------------

        if cipher_bits is not None:

            if cipher_bits >= 128:

                passed_checks.append({
                    "check": "Cipher Strength",
                    "status": "Passed",
                    "score": 10
                })

                score += 10

            else:

                failed_checks.append({
                    "check": "Cipher Strength",
                    "status": "Failed",
                    "score": -10,
                    "severity": "HIGH",
                    "how_to_fix": (
                        "Configure the server to use modern "
                        "strong TLS cipher suites with at least "
                        "128-bit encryption."
                    )
                })

                score -= 10

        else:

            failed_checks.append({
                "check": "Cipher Strength",
                "status": "Failed",
                "score": -10,
                "severity": "HIGH",
                "how_to_fix": (
                    "Configure the server with a modern "
                    "TLS cipher suite."
                )
            })

            score -= 10

        # -----------------------------------------
        # Overall SSL status
        # -----------------------------------------

        if (
            days_remaining is not None
            and days_remaining >= 0
            and cipher_bits is not None
            and cipher_bits >= 128
        ):

            status = "Secure"

        elif days_remaining is not None and days_remaining < 0:

            status = "Expired"

        else:

            status = "Needs Attention"

        # -----------------------------------------
        # Return result
        # -----------------------------------------

        return {

            "status": status,

            "hostname": hostname,

            "certificate_valid": bool(
                certificate
            ),

            "expiry_date": (
                expiry_date.strftime(
                    "%Y-%m-%d"
                )
                if expiry_date
                else None
            ),

            "days_remaining":
                days_remaining,

            "tls_version":
                tls_version,

            "cipher": {
                "name": cipher_name,
                "protocol": cipher_protocol,
                "bits": cipher_bits
            },

            "score": score,

            "passed_checks":
                passed_checks,

            "failed_checks":
                failed_checks,

            "error": None
        }

    except Exception as e:

        return {

            "status":
                "Not Secure / Unavailable",

            "hostname":
                hostname if "hostname" in locals()
                else None,

            "certificate_valid":
                False,

            "expiry_date":
                None,

            "days_remaining":
                None,

            "tls_version":
                None,

            "cipher": {
                "name": None,
                "protocol": None,
                "bits": None
            },

            "score":
                -30,

            "passed_checks":
                [],

            "failed_checks": [
                {
                    "check": "SSL/TLS Connection",
                    "status": "Failed",
                    "score": -30,
                    "severity": "HIGH",
                    "how_to_fix": (
                        "Ensure that HTTPS is enabled and that "
                        "a valid SSL/TLS certificate is correctly "
                        "configured for the website."
                    )
                }
            ],

            "error":
                str(e)
        }