/**
 * ChaosLock Frontend Application
 * Handles tab navigation, client-side previewing, password strength evaluation,
 * and AJAX interaction with the Flask cryptographic engine.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Application State in memory
  let currentOrigBlob = null;
  let currentEncBlob = null;

  // UI Element References
  const alertBanner = document.getElementById("alert-banner");
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  // Tab 1: Encrypt Elements
  const encForm = document.getElementById("encrypt-form");
  const encFileInput = document.getElementById("enc-file");
  const encPwdInput = document.getElementById("enc-password");
  const encPwdBar = document.getElementById("enc-pwd-bar");
  const encPwdHint = document.getElementById("enc-pwd-hint");
  const encSubmitBtn = document.getElementById("enc-submit-btn");
  const encOrigImg = document.getElementById("enc-orig-img");
  const encOrigFrame = document.getElementById("enc-orig-frame");
  const encOrigMeta = document.getElementById("enc-orig-meta");
  const encResImg = document.getElementById("enc-res-img");
  const encResFrame = document.getElementById("enc-res-frame");
  const encResMeta = document.getElementById("enc-res-meta");
  const encDownloadBtn = document.getElementById("enc-download-btn");
  const encSendDecryptBtn = document.getElementById("enc-send-decrypt-btn");
  const encSendAnalysisBtn = document.getElementById("enc-send-analysis-btn");

  // Tab 2: Decrypt Elements
  const decForm = document.getElementById("decrypt-form");
  const decFileInput = document.getElementById("dec-file");
  const decPwdInput = document.getElementById("dec-password");
  const decSubmitBtn = document.getElementById("dec-submit-btn");
  const decInImg = document.getElementById("dec-in-img");
  const decInFrame = document.getElementById("dec-in-frame");
  const decOutImg = document.getElementById("dec-out-img");
  const decOutFrame = document.getElementById("dec-out-frame");
  const decDownloadBtn = document.getElementById("dec-download-btn");
  const decWrongPwdBtn = document.getElementById("dec-wrong-pwd-btn");

  // Tab 3: Analysis Elements
  const anaForm = document.getElementById("analysis-form");
  const anaOrigInput = document.getElementById("ana-orig-file");
  const anaEncInput = document.getElementById("ana-enc-file");
  const anaSubmitBtn = document.getElementById("ana-submit-btn");
  const verdictBanner = document.getElementById("verdict-banner");
  const verdictStatus = document.getElementById("verdict-status");
  const verdictSummary = document.getElementById("verdict-summary");
  const metricsGrid = document.getElementById("metrics-grid");
  const valOrigEntropy = document.getElementById("val-orig-entropy");
  const valEncEntropy = document.getElementById("val-enc-entropy");
  const subEntropy = document.getElementById("sub-entropy");
  const valOrigCorr = document.getElementById("val-orig-corr");
  const valEncCorr = document.getElementById("val-enc-corr");
  const subCorr = document.getElementById("sub-corr");
  const histogramSection = document.getElementById("histogram-section");
  const histogramImg = document.getElementById("histogram-img");

  // -------------------------------------------------------------
  // 1. Tab Navigation
  // -------------------------------------------------------------
  tabButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetTabId = btn.getAttribute("data-tab");

      tabButtons.forEach((b) => {
        b.classList.remove("active");
        b.setAttribute("aria-selected", "false");
      });
      tabContents.forEach((c) => c.classList.remove("active"));

      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");
      document.getElementById(targetTabId).classList.add("active");
      hideAlert();
    });
  });

  function switchTab(tabId) {
    const btn = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
    if (btn) btn.click();
  }

  // -------------------------------------------------------------
  // 2. Alert Notification Helper
  // -------------------------------------------------------------
  function showAlert(message, type = "danger") {
    alertBanner.textContent = message;
    alertBanner.className = `alert alert-${type}`;
    alertBanner.classList.remove("hidden");
    alertBanner.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function hideAlert() {
    alertBanner.classList.add("hidden");
  }

  // -------------------------------------------------------------
  // 3. Password Toggle & Strength Meter
  // -------------------------------------------------------------
  document.querySelectorAll(".toggle-pwd-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-target");
      const input = document.getElementById(targetId);
      if (input.type === "password") {
        input.type = "text";
        btn.textContent = "\u{1F576}"; // Shades
      } else {
        input.type = "password";
        btn.textContent = "\u{1F441}"; // Eye
      }
    });
  });

  encPwdInput.addEventListener("input", () => {
    const pwd = encPwdInput.value;
    const strength = evaluatePasswordStrength(pwd);

    encPwdBar.style.width = `${strength.score}%`;
    encPwdBar.style.backgroundColor = strength.color;
    encPwdHint.textContent = `Password strength: ${strength.label} (${strength.hint})`;
  });

  function evaluatePasswordStrength(password) {
    if (!password) {
      return { score: 0, color: "#475569", label: "Empty", hint: "Enter a password" };
    }

    let score = 0;
    if (password.length >= 8) score += 25;
    if (password.length >= 14) score += 15;
    if (/[a-z]/.test(password)) score += 15;
    if (/[A-Z]/.test(password)) score += 15;
    if (/[0-9]/.test(password)) score += 15;
    if (/[^a-zA-Z0-9]/.test(password)) score += 15;

    score = Math.min(100, score);

    if (score < 40) {
      return { score, color: "#ef4444", label: "Weak", hint: "Add symbols, numbers, and length" };
    } else if (score < 75) {
      return { score, color: "#f59e0b", label: "Fair", hint: "Add mixed case and special characters" };
    } else {
      return { score, color: "#22c55e", label: "Strong", hint: "Excellent entropy for SHA-256 seeding" };
    }
  }

  // -------------------------------------------------------------
  // 4. File Input Local Preview Helpers
  // -------------------------------------------------------------
  encFileInput.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (file) {
      currentOrigBlob = file;
      renderImagePreview(file, encOrigImg, encOrigFrame, encOrigMeta);
    }
  });

  decFileInput.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (file) {
      renderImagePreview(file, decInImg, decInFrame);
    }
  });

  function renderImagePreview(fileOrBlob, imgEl, frameEl, metaEl = null) {
    const reader = new FileReader();
    reader.onload = (e) => {
      imgEl.src = e.target.result;
      imgEl.classList.remove("hidden");
      const placeholder = frameEl.querySelector(".placeholder-text");
      if (placeholder) placeholder.classList.add("hidden");

      if (metaEl && fileOrBlob.size) {
        const sizeKb = (fileOrBlob.size / 1024).toFixed(1);
        metaEl.textContent = `Size: ${sizeKb} KB | Type: ${fileOrBlob.type || "PNG"}`;
      }
    };
    reader.readAsDataURL(fileOrBlob);
  }

  // -------------------------------------------------------------
  // 5. Encrypt Flow (POST /encrypt)
  // -------------------------------------------------------------
  encForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideAlert();

    const file = encFileInput.files[0] || currentOrigBlob;
    const password = encPwdInput.value.trim();

    if (!file) {
      showAlert("Please choose an image file to encrypt.");
      return;
    }
    if (!password) {
      showAlert("Password cannot be empty.");
      return;
    }

    setButtonLoading(encSubmitBtn, true);

    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("password", password);

      const response = await fetch("/encrypt", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const errJson = await response.json();
        throw new Error(errJson.error || "Encryption failed.");
      }

      const encBlob = await response.blob();
      currentEncBlob = encBlob;

      // Update Result Preview
      const blobUrl = URL.createObjectURL(encBlob);
      encResImg.src = blobUrl;
      encResImg.classList.remove("hidden");
      const placeholder = encResFrame.querySelector(".placeholder-text");
      if (placeholder) placeholder.classList.add("hidden");

      const sizeKb = (encBlob.size / 1024).toFixed(1);
      encResMeta.textContent = `Encrypted PNG | Size: ${sizeKb} KB`;

      // Enable download link
      encDownloadBtn.href = blobUrl;
      encDownloadBtn.download = "encrypted.png";
      encDownloadBtn.classList.remove("hidden");

      // Enable quick transfer buttons
      encSendDecryptBtn.classList.remove("hidden");
      encSendAnalysisBtn.classList.remove("hidden");

      showAlert("Encryption successful! Output is lossless PNG.", "success");
    } catch (err) {
      showAlert(err.message, "danger");
    } finally {
      setButtonLoading(encSubmitBtn, false);
    }
  });

  // Transfer Encrypted Image to Decrypt Tab
  encSendDecryptBtn.addEventListener("click", () => {
    if (!currentEncBlob) return;
    renderImagePreview(currentEncBlob, decInImg, decInFrame);
    // Pre-populate password for convenient testing
    decPwdInput.value = encPwdInput.value;
    switchTab("decrypt-tab");
    showAlert("Encrypted image loaded into Decrypt tab.", "success");
  });

  // Transfer Both Images to Analysis Tab
  encSendAnalysisBtn.addEventListener("click", () => {
    if (!currentOrigBlob || !currentEncBlob) return;
    switchTab("analysis-tab");
    showAlert("Original and encrypted images loaded into Analysis tab. Click 'Run Security Verification'.", "success");
  });

  // -------------------------------------------------------------
  // 6. Decrypt Flow (POST /decrypt)
  // -------------------------------------------------------------
  decForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideAlert();

    const file = decFileInput.files[0] || currentEncBlob;
    const password = decPwdInput.value.trim();

    if (!file) {
      showAlert("Please choose an encrypted PNG file to decrypt.");
      return;
    }
    if (!password) {
      showAlert("Decryption password cannot be empty.");
      return;
    }

    setButtonLoading(decSubmitBtn, true);

    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("password", password);

      const response = await fetch("/decrypt", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const errJson = await response.json();
        throw new Error(errJson.error || "Decryption failed.");
      }

      const decBlob = await response.blob();
      const blobUrl = URL.createObjectURL(decBlob);

      decOutImg.src = blobUrl;
      decOutImg.classList.remove("hidden");
      const placeholder = decOutFrame.querySelector(".placeholder-text");
      if (placeholder) placeholder.classList.add("hidden");

      decDownloadBtn.href = blobUrl;
      decDownloadBtn.download = "decrypted.png";
      decDownloadBtn.classList.remove("hidden");

      showAlert("Decryption executed. If the password was correct, original pixels are restored; if wrong, output is pure noise.", "success");
    } catch (err) {
      showAlert(err.message, "danger");
    } finally {
      setButtonLoading(decSubmitBtn, false);
    }
  });

  // Wrong Password Demo Simulation Button
  decWrongPwdBtn.addEventListener("click", () => {
    decPwdInput.value = "IncorrectPassword_NoiseDemo999#";
    decForm.dispatchEvent(new Event("submit"));
  });

  // -------------------------------------------------------------
  // 7. Security Analysis Flow (POST /analyze)
  // -------------------------------------------------------------
  anaForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideAlert();

    const origFile = anaOrigInput.files[0] || currentOrigBlob;
    const encFile = anaEncInput.files[0] || currentEncBlob;

    if (!origFile || !encFile) {
      showAlert("Please supply both original and encrypted images for analysis.");
      return;
    }

    setButtonLoading(anaSubmitBtn, true);

    try {
      const formData = new FormData();
      formData.append("original", origFile);
      formData.append("encrypted", encFile);

      const response = await fetch("/analyze", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const errJson = await response.json();
        throw new Error(errJson.error || "Analysis failed.");
      }

      const data = await response.json();

      // Display Verdict Banner
      verdictBanner.classList.remove("hidden");
      if (data.verdict.passed) {
        verdictBanner.className = "verdict-card verdict-pass";
        verdictStatus.textContent = "PASS";
      } else {
        verdictBanner.className = "verdict-card verdict-fail";
        verdictStatus.textContent = "FAIL";
      }
      verdictSummary.textContent = data.verdict.summary;

      // Display Metrics
      metricsGrid.classList.remove("hidden");
      valOrigEntropy.textContent = data.original.entropy.overall.toFixed(4);
      valEncEntropy.textContent = data.encrypted.entropy.overall.toFixed(4);
      subEntropy.textContent = `Encrypted Channels: ${Object.entries(data.encrypted.entropy)
        .filter(([k]) => k !== "overall")
        .map(([k, v]) => `${k[0]}:${v}`)
        .join(" | ")}`;

      valOrigCorr.textContent = data.original.correlation.overall.toFixed(4);
      valEncCorr.textContent = data.encrypted.correlation.overall.toFixed(4);
      subCorr.textContent = `Encrypted Channels: ${Object.entries(data.encrypted.correlation)
        .filter(([k]) => k !== "overall")
        .map(([k, v]) => `${k[0]}:${v}`)
        .join(" | ")}`;

      // Display Comparative Histograms
      histogramSection.classList.remove("hidden");
      histogramImg.src = data.histogram_image;

      showAlert("Analysis complete. All metrics and histograms generated.", "success");
    } catch (err) {
      showAlert(err.message, "danger");
    } finally {
      setButtonLoading(anaSubmitBtn, false);
    }
  });

  // Helper for button loading states
  function setButtonLoading(button, isLoading) {
    const textSpan = button.querySelector(".btn-text");
    const spinnerSpan = button.querySelector(".btn-spinner");
    if (isLoading) {
      button.disabled = true;
      if (textSpan) textSpan.classList.add("hidden");
      if (spinnerSpan) spinnerSpan.classList.remove("hidden");
    } else {
      button.disabled = false;
      if (textSpan) textSpan.classList.remove("hidden");
      if (spinnerSpan) spinnerSpan.classList.add("hidden");
    }
  }
});

