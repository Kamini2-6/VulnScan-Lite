import React, { useState } from "react";

import {
  CircularProgressbar,
  buildStyles,
} from "react-circular-progressbar";

import "react-circular-progressbar/dist/styles.css";

import jsPDF from "jspdf";
import html2canvas from "html2canvas";

import "./App.css";

function App() {
  const [url, setUrl] = useState("");
  const [scannedUrl, setScannedUrl] = useState("");
  const [result, setResult] = useState(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showReport, setShowReport] = useState(false);

  // =====================================================
  // SCORE
  // =====================================================

  const score = Number(
    result?.percentage ??
      result?.score ??
      result?.total_score ??
      0
  );

  const getGrade = (score) => {
    if (score >= 90) return "A+";
    if (score >= 80) return "A";
    if (score >= 70) return "B";
    if (score >= 60) return "C";
    if (score >= 50) return "D";
    return "F";
  };

  const grade = result?.grade || getGrade(score);

  // =====================================================
  // RESULT DATA
  // =====================================================


  const headers =
    result?.headers?.headers ??
    result?.headers ??
    result?.header_analysis ??
    {};

  const ssl =
    result?.ssl ??
    result?.ssl_result ??
    {};

  const cms =
    result?.cms ??
    result?.cms_detection ??
    {};

  // =====================================================
  // HTTP INFORMATION
  // =====================================================

  const statusCode =
    result?.status_code ??
    result?.headers?.status_code ??
    null;

  const finalUrl =
    result?.final_url ??
    result?.headers?.final_url ??
    scannedUrl;

  // =====================================================
  // HELPER
  // =====================================================

  const formatKey = (key) => {
    return String(key)
      .replace(/_/g, " ")
      .replace(/([A-Z])/g, " $1")
      .replace(/\s+/g, " ")
      .trim()
      .replace(/\b\w/g, (char) =>
        char.toUpperCase()
      );
  };

  const formatValue = (value) => {
    if (value === null || value === undefined) {
      return "Not Available";
    }

    if (typeof value === "boolean") {
      return value ? "Yes" : "No";
    }

    if (typeof value === "object") {
      return JSON.stringify(value);
    }

    return String(value);
  };

  // =====================================================
  // HEADER STATUS
  // =====================================================

  const getHeaderStatus = (value) => {
    if (!value) {
      return "Unknown";
    }

    const status = String(
      value.status ?? ""
    ).toLowerCase();

    if (
      status === "present" ||
      status === "found" ||
      status === "passed"
    ) {
      return "Passed";
    }

    if (
      status === "missing" ||
      status === "failed"
    ) {
      return "Missing";
    }

    if (
      typeof value.score === "number" &&
      value.score > 0
    ) {
      return "Passed";
    }

    if (
      typeof value.score === "number" &&
      value.score < 0
    ) {
      return "Missing";
    }

    return value.status || "Unknown";
  };

  // =====================================================
  // HEADER SUMMARY
  // =====================================================

  const headerEntries = Object.entries(
    headers || {}
  );

  const passedHeaders = headerEntries.filter(
    ([, value]) =>
      getHeaderStatus(value) === "Passed"
  );

  const failedHeaders = headerEntries.filter(
    ([, value]) =>
      getHeaderStatus(value) === "Missing"
  );

  // =====================================================
  // SUMMARY
  // =====================================================

  const generateSummary = () => {
    if (result?.summary) {
      return result.summary;
    }

    if (score >= 90) {
      return `The website has a strong security posture based on the implemented passive security checks. The identified security controls are largely configured correctly.`;
    }

    if (score >= 75) {
      return `The website has a good security posture, but some security controls require improvement. Review the failed checks and apply the recommended fixes.`;
    }

    if (score >= 50) {
      return `The website has a moderate security posture. Several security controls require attention and should be reviewed to reduce potential security risks.`;
    }

    return `The website has a weak security posture based on the implemented security checks. Multiple security controls require attention and should be addressed.`;
  };

  // =====================================================
  // RECOMMENDATIONS
  // =====================================================

  const generateRecommendations = () => {
    const recommendations = [];

    // ---------------------------------------------------
    // Header recommendations
    // ---------------------------------------------------

    headerEntries.forEach(([name, value]) => {
      const status = getHeaderStatus(value);

      if (status !== "Missing") {
        return;
      }

      const lowerName =
        name.toLowerCase();

      if (
        lowerName.includes(
          "content-security-policy"
        )
      ) {
        recommendations.push({
          severity: "HIGH",
          title:
            "Content-Security-Policy is missing",
          finding:
            "The Content-Security-Policy security header was not detected.",
          recommendation:
            "Configure a suitable Content-Security-Policy header for the website.",
        });
      } else if (
        lowerName.includes(
          "x-frame-options"
        )
      ) {
        recommendations.push({
          severity: "MEDIUM",
          title:
            "X-Frame-Options is missing",
          finding:
            "The X-Frame-Options security header was not detected.",
          recommendation:
            "Configure X-Frame-Options or an appropriate frame-ancestors policy to reduce clickjacking risks.",
        });
      } else if (
        lowerName.includes(
          "strict-transport-security"
        )
      ) {
        recommendations.push({
          severity: "HIGH",
          title:
            "Strict-Transport-Security is missing",
          finding:
            "The HSTS security header was not detected.",
          recommendation:
            "Enable HTTPS and configure Strict-Transport-Security after confirming the website works correctly over HTTPS.",
        });
      } else {
        recommendations.push({
          severity: "MEDIUM",
          title: `${formatKey(name)} is missing`,
          finding: `The ${formatKey(
            name
          )} security control was not detected.`,
          recommendation: `Review and configure ${formatKey(
            name
          )} where appropriate.`,
        });
      }
    });

    // ---------------------------------------------------
    // SSL recommendation
    // ---------------------------------------------------

    const sslText =
      JSON.stringify(ssl).toLowerCase();

    if (
      ssl?.valid === false ||
      ssl?.secure === false ||
      String(
        ssl?.status ?? ""
      ).toLowerCase() === "invalid" ||
      String(
        ssl?.status ?? ""
      ).toLowerCase() === "failed" ||
      sslText.includes("expired") ||
      sslText.includes(
        "invalid certificate"
      )
    ) {
      recommendations.push({
        severity: "HIGH",
        title:
          "SSL/TLS configuration requires attention",
        finding:
          "The SSL/TLS inspection indicates a possible certificate or HTTPS configuration problem.",
        recommendation:
          "Verify certificate validity, expiration date, hostname matching and HTTPS configuration.",
      });
    }

    // ---------------------------------------------------
    // CMS recommendation
    // ---------------------------------------------------

    const cmsText =
      JSON.stringify(cms).toLowerCase();

    const cmsDetected =
      cms?.detected === true ||
      cms?.cms_detected === true ||
      Boolean(cms?.name) ||
      Boolean(cms?.cms) ||
      cmsText.includes("wordpress") ||
      cmsText.includes("drupal") ||
      cmsText.includes("joomla");

    if (cmsDetected) {
      recommendations.push({
        severity: "MEDIUM",
        title: "CMS detected",
        finding:
          "A CMS technology was identified during passive analysis.",
        recommendation:
          "Keep the CMS core, plugins, themes and extensions updated. Remove unused components.",
      });
    }

    // ---------------------------------------------------
    // Default
    // ---------------------------------------------------

    if (recommendations.length === 0) {
      recommendations.push({
        severity: "LOW",
        title:
          "Maintain the current security posture",
        finding:
          "No additional recommendation was generated from the available scan results.",
        recommendation:
          "Continue applying security updates and perform periodic security assessments.",
      });
    }

    return recommendations;
  };

  const recommendations =
    generateRecommendations();

  // =====================================================
  // START SCAN
  // =====================================================

  const scanWebsite = async () => {
    if (!url.trim()) {
      setError(
        "Please enter a website URL."
      );
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);
    setShowReport(false);

    let scanUrl = url.trim();

    if (
      !scanUrl.startsWith("http://") &&
      !scanUrl.startsWith("https://")
    ) {
      scanUrl =
        "https://" + scanUrl;
    }

    setScannedUrl(scanUrl);

    try {
      const response = await fetch(
        "http://127.0.0.1:8000/scan",
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/json",
          },

          body: JSON.stringify({
            url: scanUrl,
          }),
        }
      );

      if (!response.ok) {
        throw new Error(
          "Unable to start the scan."
        );
      }

      const data =
        await response.json();

      if (!data.task_id) {
        throw new Error(
          "Task ID was not returned by the server."
        );
      }

      pollStatus(data.task_id);
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          "Something went wrong."
      );

      setLoading(false);
    }
  };

  // =====================================================
  // CELERY POLLING
  // =====================================================

  const pollStatus = async (
    taskId
  ) => {
    try {
      const response = await fetch(
        `http://127.0.0.1:8000/status/${taskId}`
      );

      if (!response.ok) {
        throw new Error(
          "Unable to get scan status."
        );
      }

      const data =
        await response.json();

      console.log(
        "Scan status:",
        data
      );

      if (
        data.status === "completed" ||
        data.status === "SUCCESS"
      ) {
        if (!data.result) {
          throw new Error(
            "Scan completed but no result was returned."
          );
        }

        console.log(
          "Real scan result:",
          data.result
        );

        setResult(data.result);
        setLoading(false);
        setShowReport(true);

        return;
      }

      if (
        data.status === "failed" ||
        data.status === "failure" ||
        data.status === "FAILURE"
      ) {
        setError(
          data.error ||
            "The website scan failed."
        );

        setLoading(false);

        return;
      }

      setTimeout(() => {
        pollStatus(taskId);
      }, 2000);
    } catch (err) {
      console.error(
        "Polling error:",
        err
      );

      setError(
        err.message ||
          "Unable to fetch scan result."
      );

      setLoading(false);
    }
  };

  // =====================================================
  // PDF
  // =====================================================

  const exportPDF = async () => {
    const report =
      document.getElementById(
        "security-report"
      );

    if (!report) {
      alert(
        "Security report not found."
      );
      return;
    }

    try {
      const canvas =
        await html2canvas(report, {
          scale: 2,
          useCORS: true,
          backgroundColor:
            "#ffffff",
        });

      const image =
        canvas.toDataURL(
          "image/png"
        );

      const pdf = new jsPDF(
        "p",
        "mm",
        "a4"
      );

      const pageWidth =
        pdf.internal.pageSize.getWidth();

      const pageHeight =
        pdf.internal.pageSize.getHeight();

      const imageWidth =
        pageWidth;

      const imageHeight =
        (canvas.height *
          imageWidth) /
        canvas.width;

      let heightLeft =
        imageHeight;

      let position = 0;

      pdf.addImage(
        image,
        "PNG",
        0,
        position,
        imageWidth,
        imageHeight
      );

      heightLeft -=
        pageHeight;

      while (
        heightLeft > 0
      ) {
        position =
          heightLeft -
          imageHeight;

        pdf.addPage();

        pdf.addImage(
          image,
          "PNG",
          0,
          position,
          imageWidth,
          imageHeight
        );

        heightLeft -=
          pageHeight;
      }

      pdf.save(
        "VulnScan-Security-Report.pdf"
      );
    } catch (err) {
      console.error(
        "PDF error:",
        err
      );

      alert(
        "Unable to generate PDF."
      );
    }
  };

  // =====================================================
  // NEW SCAN
  // =====================================================

  const scanAnother = () => {
    setShowReport(false);
    setResult(null);
    setUrl("");
    setScannedUrl("");
    setError("");
  };

  // =====================================================
  // REPORT PAGE
  // =====================================================

  if (
    showReport &&
    result
  ) {
    return (
      <div className="app">

        {/* =================================================
            REPORT TOPBAR
        ================================================= */}

        <header className="report-topbar">

          <div>
            <h1>
              🛡️ VulnScan Lite
            </h1>

            <p>
              Security Health Report
            </p>
          </div>

          <button
            className="back-button"
            onClick={
              scanAnother
            }
          >
            ← Scan Another URL
          </button>

        </header>

        <main className="report-container">

          <div
            id="security-report"
            className="report-card"
          >

            {/* =================================================
                REPORT HEADER
            ================================================= */}

            <div className="report-heading">

              <div>

                <span className="report-label">
                  SECURITY ASSESSMENT
                </span>

                <h1>
                  Security Health Report
                </h1>

                <p className="scanned-url">
                  {finalUrl}
                </p>

              </div>

              <div className="report-date">

                <strong>
                  Scan Date
                </strong>

                <span>
                  {new Date().toLocaleString()}
                </span>

              </div>

            </div>

            {/* =================================================
                SCORE
            ================================================= */}

            <div className="score-card">

              <div className="score-progress">

                <CircularProgressbar
                  value={Math.max(
                    0,
                    Math.min(
                      100,
                      score
                    )
                  )}

                  text={`${Math.round(
                    score
                  )}`}

                  styles={buildStyles({

                    pathColor:
                      score >= 75
                        ? "#16a34a"
                        : score >= 50
                        ? "#f59e0b"
                        : "#dc2626",

                    textColor:
                      "#111827",

                    trailColor:
                      "#e5e7eb",
                  })}
                />

              </div>

              <div className="score-content">

                <span className="small-heading">
                  OVERALL SECURITY SCORE
                </span>

                <h2>
                  {score}/100
                </h2>

                <div
                  className={`grade-badge grade-${String(
                    grade
                  )
                    .replace(
                      "+",
                      "plus"
                    )
                    .toLowerCase()}`}
                >
                  Grade {grade}
                </div>

              </div>

            </div>

            {/* =================================================
                SUMMARY
            ================================================= */}

            <section className="report-section">

              <h2>
                📊 Overall Summary
              </h2>

              <div className="summary">

                <p>
                  {generateSummary()}
                </p>

              </div>

            </section>

            {/* =================================================
                SCAN OVERVIEW
            ================================================= */}

            <section className="report-section">

              <h2>
                🔍 Scan Overview
              </h2>

              <div className="findings-grid">

                <div className="finding-card">

                  <span className="finding-icon">
                    🛡️
                  </span>

                  <h3>
                    Technical Security
                  </h3>

                  <p>
                    {passedHeaders.length}{" "}
                    security header
                    {passedHeaders.length !==
                    1
                      ? "s"
                      : ""}{" "}
                    passed and{" "}
                    {failedHeaders.length}{" "}
                    require attention.
                  </p>

                </div>

                <div className="finding-card">

                  <span className="finding-icon">
                    🔒
                  </span>

                  <h3>
                    SSL/TLS
                  </h3>

                  <p>
                    Passive certificate
                    and HTTPS inspection
                    completed.
                  </p>

                </div>

                <div className="finding-card">

                  <span className="finding-icon">
                    🌐
                  </span>

                  <h3>
                    CMS Detection
                  </h3>

                  <p>
                    Website technology
                    was checked using
                    passive indicators.
                  </p>

                </div>

              </div>

            </section>

            {/* =================================================
                TECHNICAL SECURITY
            ================================================= */}

            <section className="report-section">

              <h2>
                🛡️ Technical Security
              </h2>

              <p className="recommendation-intro">
                Security headers detected
                from the actual scanned
                website.
              </p>

              <div className="header-results">

                {headerEntries.length >
                0 ? (

                  headerEntries.map(
                    ([name, value]) => {

                      const status =
                        getHeaderStatus(
                          value
                        );

                      const passed =
                        status ===
                        "Passed";

                      return (
                        <div
                          className={`header-result-row ${
                            passed
                              ? "header-passed"
                              : "header-failed"
                          }`}
                          key={name}
                        >

                          <div className="header-info">

                            <strong>
                              {formatKey(
                                name
                              )}
                            </strong>

                            <span>
                              {value?.value !==
                                null &&
                              value?.value !==
                                undefined &&
                              value?.value !==
                                ""
                                ? String(
                                    value.value
                                  )
                                : "Header value not exposed"}
                            </span>

                          </div>

                          <div className="header-status">

                            <span
                              className={
                                passed
                                  ? "status-pass"
                                  : "status-fail"
                              }
                            >
                              {passed
                                ? "✓ Passed"
                                : "✗ Missing"}
                            </span>

                            <small>
                              Score:{" "}
                              {value?.score ??
                                0}
                            </small>

                          </div>

                        </div>
                      );
                    }
                  )

                ) : (

                  <div className="details-box">
                    No security header
                    information was
                    returned by the
                    scanner.
                  </div>

                )}

              </div>

            </section>

            {/* =================================================
                HTTP INFORMATION
            ================================================= */}

            <section className="report-section">

              <h2>
                🌐 HTTP Information
              </h2>

              <div className="details-box">

                <div className="detail-row">

                  <strong>
                    HTTP Status
                  </strong>

                  <span>

                    {statusCode ??
                      "Not Available"}

                    {statusCode ===
                      200 && (
                      <span className="status-pass">
                        {" "}
                        ✓ OK
                      </span>
                    )}

                    {statusCode >=
                      300 &&
                      statusCode <
                        400 && (
                        <span className="status-pass">
                          {" "}
                          ↪ Redirect
                        </span>
                      )}

                    {statusCode >=
                      400 &&
                      statusCode <
                        500 && (
                        <span className="status-fail">
                          {" "}
                          ✗ Client Error
                        </span>
                      )}

                    {statusCode >=
                      500 && (
                        <span className="status-fail">
                          {" "}
                          ✗ Server Error
                        </span>
                      )}

                  </span>

                </div>

                <div className="detail-row">

                  <strong>
                    Final URL
                  </strong>

                  <span>
                    {finalUrl ||
                      "Not Available"}
                  </span>

                </div>

              </div>

            </section>

            {/* =================================================
                SSL
            ================================================= */}

            <section className="report-section">

              <h2>
                🔒 SSL/TLS Inspection
              </h2>

              <div className="details-box">

                {Object.keys(
                  ssl || {}
                ).length > 0 ? (

                  Object.entries(
                    ssl
                  ).map(
                    ([key, value]) => (

                      <div
                        className="detail-row"
                        key={key}
                      >

                        <strong>
                          {formatKey(
                            key
                          )}
                        </strong>

                        <span>
                          {formatValue(
                            value
                          )}
                        </span>

                      </div>

                    )
                  )

                ) : (

                  <p>
                    SSL/TLS information
                    was not returned
                    by the scanner.
                  </p>

                )}

              </div>

            </section>

            {/* =================================================
                CMS
            ================================================= */}

            <section className="report-section">

              <h2>
                🌐 CMS Detection
              </h2>

              <div className="details-box">

                {Object.keys(
                  cms || {}
                ).length > 0 ? (

                  Object.entries(
                    cms
                  ).map(
                    ([key, value]) => (

                      <div
                        className="detail-row"
                        key={key}
                      >

                        <strong>
                          {formatKey(
                            key
                          )}
                        </strong>

                        <span>
                          {formatValue(
                            value
                          )}
                        </span>

                      </div>

                    )
                  )

                ) : (

                  <p>
                    No CMS was identified
                    from the available
                    passive indicators.
                  </p>

                )}

              </div>

            </section>

            {/* =================================================
                FAILED CHECKS
            ================================================= */}

            <section className="report-section">

              <h2>
                ❌ Failed Checks
              </h2>

              {failedHeaders.length >
              0 ? (

                <div className="recommendations">

                  {failedHeaders.map(
                    ([name, value]) => (

                      <div
                        className="recommendation-card"
                        key={name}
                      >

                        <div className="recommendation-header">

                          <span className="severity severity-high">
                            FAILED
                          </span>

                          <h3>
                            {formatKey(
                              name
                            )}
                          </h3>

                        </div>

                        <div className="recommendation-content">

                          <p>
                            <strong>
                              Status:
                            </strong>{" "}
                            {value?.status ||
                              "Missing"}
                          </p>

                          <p>
                            <strong>
                              Score:
                            </strong>{" "}
                            {value?.score ??
                              0}
                          </p>

                        </div>

                      </div>

                    )
                  )}

                </div>

              ) : (

                <div className="summary">

                  <p>
                    ✓ No failed security
                    header checks were
                    identified.
                  </p>

                </div>

              )}

            </section>

            {/* =================================================
                RECOMMENDATIONS
            ================================================= */}

            <section className="report-section">

              <h2>
                💡 How to Fix
              </h2>

              <p className="recommendation-intro">
                Recommendations are
                generated from the actual
                findings returned by the
                scanner.
              </p>

              <div className="recommendations">

                {recommendations.map(
                  (item, index) => (

                    <div
                      className="recommendation-card"
                      key={index}
                    >

                      <div className="recommendation-header">

                        <span
                          className={`severity severity-${String(
                            item.severity
                          ).toLowerCase()}`}
                        >
                          {item.severity}
                        </span>

                        <h3>
                          {item.title}
                        </h3>

                      </div>

                      <div className="recommendation-content">

                        <p>
                          <strong>
                            Finding:
                          </strong>{" "}
                          {item.finding}
                        </p>

                        <p>
                          <strong>
                            How to Fix:
                          </strong>{" "}
                          {item.recommendation}
                        </p>

                      </div>

                    </div>

                  )
                )}

              </div>

            </section>

            {/* =================================================
                CONCLUSION
            ================================================= */}

            <section className="conclusion">

              <h2>
                Conclusion
              </h2>

              <p>
                VulnScan Lite completed a
                passive security assessment
                of{" "}
                <strong>
                  {finalUrl}
                </strong>
                .
              </p>

              <p>
                The report is based on the
                actual HTTP headers, SSL/TLS
                inspection and CMS indicators
                returned by the scanner.
              </p>

            </section>

          </div>

          {/* =================================================
              ACTIONS
          ================================================= */}

          <div className="report-actions">

            <button
              className="pdf-button"
              onClick={exportPDF}
            >
              📄 Export PDF Report
            </button>

            <button
              className="new-scan-button"
              onClick={scanAnother}
            >
              🔍 Scan Another Website
            </button>

          </div>

        </main>

      </div>
    );
  }

  // =====================================================
  // SCANNER PAGE
  // =====================================================

  return (
    <div className="app">

      <header className="main-header">

        <div className="header-content">

          <div className="logo">
            🛡️
          </div>

          <div>

            <h1>
              VulnScan Lite
            </h1>

            <p>
              Website Security Health
              Scanner
            </p>

          </div>

        </div>

      </header>

      <main className="scanner-container">

        <div className="scanner-hero">

          <div className="hero-badge">
            🔐 Passive Security Assessment
          </div>

          <h2>
            Check Your Website's
            <span>
              {" "}
              Security Posture
            </span>
          </h2>

          <p>
            Analyze security headers,
            SSL/TLS configuration and
            CMS information using a
            safe, non-aggressive scan.
          </p>

          <div className="scanner-box">

            <input
              type="text"
              value={url}
              onChange={(e) =>
                setUrl(
                  e.target.value
                )
              }
              placeholder="https://example.com"
              disabled={loading}
            />

            <button
              onClick={scanWebsite}
              disabled={loading}
            >
              {loading
                ? "Scanning..."
                : "🔍 Start Scan"}
            </button>

          </div>

          {error && (
            <div className="error-box">
              {error}
            </div>
          )}

        </div>

        {/* =================================================
            LOADING
        ================================================= */}

        {loading && (

          <div className="loading-section">

            <div className="loading-spinner"></div>

            <h3>
              Security scan in progress...
            </h3>

            <p>
              VulnScan Lite is scanning
              the website and analyzing
              its security configuration.
            </p>

            <div className="loading-steps">

              <span>
                ✓ Request received
              </span>

              <span>
                ✓ Scan queued through Celery
              </span>

              <span>
                ⏳ Analyzing real website data
              </span>

            </div>

          </div>

        )}

      </main>

    </div>
  );
}

export default App;