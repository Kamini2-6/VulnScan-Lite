import React, { useState } from "react";

// =====================================================
// DISCLAIMER BANNER
// Legal/ethical requirement (Deliverable #2):
// "Only scan websites you own. This tool performs
//  passive analysis only."
// Persists dismissal in memory only (not localStorage,
// since it must reappear each fresh session/visit).
// =====================================================

function DisclaimerBanner() {
  const [dismissed, setDismissed] = useState(false);

  if (dismissed) {
    return null;
  }

  return (
    <div className="disclaimer-banner" role="alert">
      <span className="disclaimer-icon">⚠️</span>

      <p>
        <strong>Only scan websites you own or have explicit permission to test.</strong>{" "}
        VulnScan Lite performs passive analysis only (headers, SSL/TLS, CMS
        fingerprinting) — it never attempts exploitation or intrusive attacks.
      </p>

      <button
        className="disclaimer-close"
        onClick={() => setDismissed(true)}
        aria-label="Dismiss disclaimer"
      >
        ✕
      </button>
    </div>
  );
}

export default DisclaimerBanner;