import re
import requests
from bs4 import BeautifulSoup


# Minimum versions considered acceptable for this project.
# These can be updated later as the project is maintained.
MIN_SUPPORTED_VERSIONS = {
    "WordPress": (6, 0, 0),
    "Drupal": (10, 0, 0),
    "Joomla": (4, 0, 0),
}


def parse_version(version_string):
    """
    Convert a version string such as:
    6.4.2 -> (6, 4, 2)
    """

    if not version_string:
        return None

    match = re.search(
        r"(\d+)(?:\.(\d+))?(?:\.(\d+))?",
        version_string
    )

    if not match:
        return None

    major = int(match.group(1))
    minor = int(match.group(2) or 0)
    patch = int(match.group(3) or 0)

    return major, minor, patch


def detect_cms(url: str):

    try:

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "VulnScan-Lite/1.0"
            }
        )

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        cms = "Unknown"
        version = None
        detection_method = None

        # ==================================================
        # 1. META GENERATOR DETECTION
        # ==================================================

        generator = soup.find(
            "meta",
            attrs={
                "name": re.compile(
                    "^generator$",
                    re.I
                )
            }
        )

        if generator and generator.get("content"):

            content = generator.get(
                "content"
            ).strip()

            content_lower = content.lower()

            if "wordpress" in content_lower:

                cms = "WordPress"
                detection_method = (
                    "HTML meta generator"
                )

            elif "joomla" in content_lower:

                cms = "Joomla"
                detection_method = (
                    "HTML meta generator"
                )

            elif "drupal" in content_lower:

                cms = "Drupal"
                detection_method = (
                    "HTML meta generator"
                )

            else:

                cms = content
                detection_method = (
                    "HTML meta generator"
                )

            # Try to extract version
            version = parse_version(
                content
            )

        # ==================================================
        # 2. X-POWERED-BY DETECTION
        # ==================================================

        powered_by = response.headers.get(
            "X-Powered-By",
            ""
        ).strip()

        powered_lower = powered_by.lower()

        if powered_by:

            if "wordpress" in powered_lower:

                cms = "WordPress"

                if not detection_method:
                    detection_method = (
                        "X-Powered-By header"
                    )

                version = (
                    parse_version(powered_by)
                    or version
                )

            elif "joomla" in powered_lower:

                cms = "Joomla"

                if not detection_method:
                    detection_method = (
                        "X-Powered-By header"
                    )

                version = (
                    parse_version(powered_by)
                    or version
                )

            elif "drupal" in powered_lower:

                cms = "Drupal"

                if not detection_method:
                    detection_method = (
                        "X-Powered-By header"
                    )

                version = (
                    parse_version(powered_by)
                    or version
                )

        # ==================================================
        # 3. WORDPRESS GENERATOR ADDITIONAL CHECK
        # ==================================================

        if cms == "Unknown":

            wordpress_generator = soup.find(
                "meta",
                attrs={
                    "name": "generator"
                }
            )

            if wordpress_generator:

                content = (
                    wordpress_generator
                    .get("content", "")
                )

                if "wordpress" in content.lower():

                    cms = "WordPress"

                    detection_method = (
                        "HTML meta generator"
                    )

                    version = parse_version(
                        content
                    )

        # ==================================================
        # 4. VERSION STATUS
        # ==================================================

        version_status = "Unknown"
        cms_score = 0

        passed_checks = []
        failed_checks = []

        how_to_fix = None
        severity = None

        if cms in MIN_SUPPORTED_VERSIONS:

            minimum_version = (
                MIN_SUPPORTED_VERSIONS[cms]
            )

            if version:

                if version >= minimum_version:

                    version_status = "Supported"

                    cms_score = 20

                    passed_checks.append({
                        "check": (
                            f"{cms} version"
                        ),
                        "status": "Passed",
                        "score": 20
                    })

                else:

                    version_status = "Outdated"

                    cms_score = -20

                    severity = "HIGH"

                    how_to_fix = (
                        f"Update {cms} to a current "
                        "supported release. Before "
                        "upgrading, create a backup and "
                        "verify that themes, plugins, "
                        "extensions, and application "
                        "components remain compatible."
                    )

                    failed_checks.append({
                        "check": (
                            f"{cms} version"
                        ),
                        "status": "Failed",
                        "score": -20,
                        "severity": severity,
                        "how_to_fix": how_to_fix
                    })

            else:

                version_status = (
                    "Version Not Identified"
                )

                # CMS detected but exact version
                # cannot be safely determined.
                cms_score = 0

                failed_checks.append({
                    "check": (
                        f"{cms} version detection"
                    ),
                    "status": "Not Verified",
                    "score": 0,
                    "severity": "LOW",
                    "how_to_fix": (
                        f"Verify the installed {cms} "
                        "version from the website's "
                        "administration or server "
                        "environment and ensure it is "
                        "fully updated."
                    )
                })

        elif cms != "Unknown":

            # Unknown CMS versioning scheme
            version_status = (
                "Version Not Evaluated"
            )

            cms_score = 0

            failed_checks.append({
                "check": "CMS version",
                "status": "Not Verified",
                "score": 0,
                "severity": "LOW",
                "how_to_fix": (
                    "Verify the detected CMS and "
                    "ensure that its core, themes, "
                    "plugins, and extensions are "
                    "updated to supported releases."
                )
            })

        else:

            # No identifiable CMS
            version_status = "Not Detected"

            cms_score = 0

            passed_checks.append({
                "check": "CMS Exposure",
                "status": "No identifiable CMS detected",
                "score": 0
            })

        # ==================================================
        # 5. RETURN RESULT
        # ==================================================

        return {

            "cms": cms,

            "version": (
                ".".join(
                    map(str, version)
                )
                if version
                else None
            ),

            "version_status":
                version_status,

            "detection_method":
                detection_method,

            "powered_by":
                powered_by or None,

            "score":
                cms_score,

            "passed_checks":
                passed_checks,

            "failed_checks":
                failed_checks,

            "error":
                None
        }

    except requests.exceptions.RequestException as e:

        return {

            "cms":
                "Unknown",

            "version":
                None,

            "version_status":
                "Unavailable",

            "detection_method":
                None,

            "powered_by":
                None,

            "score":
                0,

            "passed_checks":
                [],

            "failed_checks": [
                {
                    "check": "CMS Detection",
                    "status": "Failed",
                    "score": 0,
                    "severity": "LOW",
                    "how_to_fix": (
                        "Verify that the website is "
                        "reachable and try the scan again."
                    )
                }
            ],

            "error":
                str(e)
        }