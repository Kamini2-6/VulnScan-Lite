from Scanner.Header_analysis_script import check_headers
from Scanner.ssl_inspection import check_ssl
from Scanner.cms_detection import detect_cms


def get_grade(percentage):
    """
    Convert security percentage into a professional grade.
    """

    if percentage >= 90:
        return "A+"
    elif percentage >= 80:
        return "A"
    elif percentage >= 70:
        return "B+"
    elif percentage >= 60:
        return "B"
    elif percentage >= 50:
        return "C"
    elif percentage >= 40:
        return "D"
    else:
        return "F"


def get_security_status(percentage):
    """
    Human-readable security status.
    """

    if percentage >= 90:
        return "Excellent"
    elif percentage >= 80:
        return "Very Good"
    elif percentage >= 70:
        return "Good"
    elif percentage >= 60:
        return "Fair"
    elif percentage >= 40:
        return "Needs Improvement"
    else:
        return "Poor"


def create_summary(percentage, passed_count, failed_count):
    """
    Generate a dynamic overall security summary.
    """

    if percentage >= 90:
        return (
            f"The website demonstrates an excellent security posture. "
            f"{passed_count} security checks passed and "
            f"{failed_count} checks require attention."
        )

    elif percentage >= 80:
        return (
            f"The website has a strong overall security posture. "
            f"{passed_count} security checks passed, while "
            f"{failed_count} checks require attention."
        )

    elif percentage >= 70:
        return (
            f"The website has a generally good security posture, "
            f"but some security improvements are recommended. "
            f"{passed_count} checks passed and "
            f"{failed_count} checks require attention."
        )

    elif percentage >= 60:
        return (
            f"The website has a fair security posture. "
            f"Several security controls should be reviewed. "
            f"{passed_count} checks passed and "
            f"{failed_count} checks require attention."
        )

    elif percentage >= 40:
        return (
            f"The website needs security improvements. "
            f"Multiple checks require remediation. "
            f"{passed_count} checks passed and "
            f"{failed_count} checks failed."
        )

    else:
        return (
            f"The website has a poor security posture. "
            f"Several important security controls require "
            f"immediate attention. "
            f"{passed_count} checks passed and "
            f"{failed_count} checks failed."
        )


def scan_site(url: str):

    print(f"[*] Starting scan: {url}")

    # ==================================================
    # HEADER ANALYSIS
    # ==================================================

    try:

        header_result = check_headers(url)

        print("[+] Header analysis completed")

    except Exception as e:

        print(
            f"[ERROR] Header analysis failed: {e}"
        )

        header_result = {
            "headers": {},
            "score": 0,
            "passed_checks": [],
            "failed_checks": [],
            "error": str(e)
        }

    # ==================================================
    # CMS DETECTION
    # ==================================================

    try:

        cms_result = detect_cms(url)

        print("[+] CMS detection completed")

    except Exception as e:

        print(
            f"[ERROR] CMS detection failed: {e}"
        )

        cms_result = {
            "cms": "Unknown",
            "version": None,
            "version_status": "Unavailable",
            "powered_by": None,
            "score": 0,
            "passed_checks": [],
            "failed_checks": [],
            "error": str(e)
        }

    # ==================================================
    # SSL/TLS INSPECTION
    # ==================================================

    try:

        ssl_result = check_ssl(url)

        print("[+] SSL inspection completed")

    except Exception as e:

        print(
            f"[ERROR] SSL inspection failed: {e}"
        )

        ssl_result = {
            "status": "Unavailable",
            "expiry_date": None,
            "days_remaining": None,
            "tls_version": None,
            "cipher": {
                "name": None,
                "protocol": None,
                "bits": None
            },
            "score": -30,
            "passed_checks": [],
            "failed_checks": [],
            "error": str(e)
        }

    # ==================================================
    # RAW SCORE
    # ==================================================

    header_score = header_result.get(
        "score",
        0
    )

    ssl_score = ssl_result.get(
        "score",
        0
    )

    cms_score = cms_result.get(
        "score",
        0
    )

    raw_score = (
        header_score
        + ssl_score
        + cms_score
    )

    # ==================================================
    # RAW SCORE RANGE
    #
    # Headers = -30 to +30
    # SSL     = -30 to +30
    # CMS     = -20 to +20
    #
    # Total   = -80 to +80
    # ==================================================

    minimum_raw_score = -80
    maximum_raw_score = 80

    # ==================================================
    # CONVERT RAW SCORE TO 0-100
    # ==================================================

    percentage = (
        (
            raw_score
            - minimum_raw_score
        )
        /
        (
            maximum_raw_score
            - minimum_raw_score
        )
    ) * 100

    # Keep score safely between 0 and 100

    percentage = max(
        0,
        min(
            100,
            percentage
        )
    )

    percentage = round(
        percentage,
        2
    )

    # ==================================================
    # RISK PERCENTAGE
    # ==================================================

    risk_percentage = round(
        100 - percentage,
        2
    )

    # ==================================================
    # GRADE
    # ==================================================

    grade = get_grade(
        percentage
    )

    security_status = get_security_status(
        percentage
    )

    # ==================================================
    # PASSED CHECKS
    # ==================================================

    passed_checks = []

    passed_checks.extend(
        header_result.get(
            "passed_checks",
            []
        )
    )

    passed_checks.extend(
        ssl_result.get(
            "passed_checks",
            []
        )
    )

    passed_checks.extend(
        cms_result.get(
            "passed_checks",
            []
        )
    )

    # ==================================================
    # FAILED CHECKS
    # ==================================================

    failed_checks = []

    failed_checks.extend(
        header_result.get(
            "failed_checks",
            []
        )
    )

    failed_checks.extend(
        ssl_result.get(
            "failed_checks",
            []
        )
    )

    failed_checks.extend(
        cms_result.get(
            "failed_checks",
            []
        )
    )

    # ==================================================
    # RECOMMENDATIONS
    # ==================================================

    recommendations = []

    for check in failed_checks:

        recommendation = {
            "check": check.get(
                "check",
                "Security Check"
            ),

            "severity": check.get(
                "severity",
                "MEDIUM"
            ),

            "status": check.get(
                "status",
                "Failed"
            ),

            "how_to_fix": check.get(
                "how_to_fix",
                "Review the security configuration "
                "and apply the recommended remediation."
            )
        }

        recommendations.append(
            recommendation
        )

    # ==================================================
    # COUNTS
    # ==================================================

    passed_count = len(
        passed_checks
    )

    failed_count = len(
        failed_checks
    )

    # ==================================================
    # OVERALL SUMMARY
    # ==================================================

    overall_summary = create_summary(
        percentage,
        passed_count,
        failed_count
    )

    # ==================================================
    # FINAL RESULT
    # ==================================================

    result = {

        "url": url,

        "score": round(
            percentage,
            2
        ),

        "raw_score": raw_score,

        "max_score": 100,

        "percentage": percentage,

        "risk_percentage":
            risk_percentage,

        "grade": grade,

        "status":
            security_status,

        "summary":
            overall_summary,

        "passed_count":
            passed_count,

        "failed_count":
            failed_count,

        "passed_checks":
            passed_checks,

        "failed_checks":
            failed_checks,

        "recommendations":
            recommendations,

        "headers":
            header_result.get("headers",{}),


    "header_score": header_result.get(
        "score",
        0
    ),

      "status_code": header_result.get(
        "status_code"
    ),

    "final_url": header_result.get(
        "final_url",
        url
    ),
        "ssl":
            ssl_result,

        "cms":
            cms_result
    }

    print(
        f"[+] Scan completed successfully "
        f"| Score: {percentage}/100 "
        f"| Grade: {grade}"
    )

    return result