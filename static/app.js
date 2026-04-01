const scanBtn = document.getElementById("scan-btn");
const scanInput = document.getElementById("scan-input");
const scanResult = document.getElementById("scan-result");
const riskBadge = document.getElementById("risk-badge");
const riskScore = document.getElementById("risk-score");
const meterFill = document.getElementById("meter-fill");
const riskExplanation = document.getElementById("risk-explanation");
const riskReasons = document.getElementById("risk-reasons");
const riskImpact = document.getElementById("risk-impact");

const imageInput = document.getElementById("image-input");
const imagePreview = document.getElementById("image-preview");
const imageBtn = document.getElementById("image-btn");
const imageResult = document.getElementById("image-result");
const imageBadge = document.getElementById("image-badge");
const imageScore = document.getElementById("image-score");
const imageMeterFill = document.getElementById("image-meter-fill");
const imageExplanation = document.getElementById("image-explanation");
const imageReasons = document.getElementById("image-reasons");
const imageImpact = document.getElementById("image-impact");

const setBadge = (badge, meter, label) => {
  badge.textContent = label;
  if (label === "SAFE" || label === "REAL") {
    badge.style.background = "var(--safe)";
    badge.style.color = "#03190b";
    meter.style.background = "var(--safe)";
  } else if (label === "SUSPICIOUS" || label === "POSSIBLY FAKE") {
    badge.style.background = "var(--warn)";
    badge.style.color = "#1a1201";
    meter.style.background = "var(--warn)";
  } else {
    badge.style.background = "var(--danger)";
    badge.style.color = "#1a0306";
    meter.style.background = "var(--danger)";
  }
};

const showResult = (card) => {
  card.classList.remove("hidden");
  setTimeout(() => card.classList.add("show"), 40);
};

const clearList = (list) => {
  list.innerHTML = "";
};

scanBtn.addEventListener("click", async () => {
  const text = scanInput.value.trim();
  if (!text) {
    alert("Please paste a message or link first.");
    return;
  }

  scanBtn.textContent = "Scanning...";
  scanBtn.disabled = true;

  try {
    const response = await fetch("/api/scan-text", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });

    const contentType = response.headers.get("Content-Type") || "";
    const data = contentType.includes("application/json")
      ? await response.json()
      : { error: await response.text() };
    if (!response.ok) throw new Error(data.error || "Scan failed");

    setBadge(riskBadge, meterFill, data.risk_level);
    riskScore.textContent = `Confidence: ${data.confidence}%`;
    meterFill.style.width = `${data.confidence}%`;
    riskExplanation.textContent = data.explanation;
    clearList(riskReasons);
    data.reasons.forEach((reason) => {
      const li = document.createElement("li");
      li.textContent = reason;
      riskReasons.appendChild(li);
    });
    riskImpact.textContent = data.impact;
    showResult(scanResult);
  } catch (error) {
    alert(error.message);
  } finally {
    scanBtn.textContent = "Scan Threat";
    scanBtn.disabled = false;
  }
});

imageInput.addEventListener("change", () => {
  const file = imageInput.files[0];
  if (!file) return;
  const url = URL.createObjectURL(file);
  imagePreview.src = url;
  imagePreview.style.display = "block";
});

imageBtn.addEventListener("click", async () => {
  const file = imageInput.files[0];
  if (!file) {
    alert("Please choose an image first.");
    return;
  }

  imageBtn.textContent = "Analyzing...";
  imageBtn.disabled = true;

  const formData = new FormData();
  formData.append("image", file);

  try {
    const response = await fetch("/api/scan-image", {
      method: "POST",
      body: formData,
    });

    const contentType = response.headers.get("Content-Type") || "";
    const data = contentType.includes("application/json")
      ? await response.json()
      : { error: await response.text() };
    if (!response.ok) throw new Error(data.error || "Scan failed");

    setBadge(imageBadge, imageMeterFill, data.label);
    imageScore.textContent = `Confidence: ${data.confidence}%`;
    imageMeterFill.style.width = `${data.confidence}%`;
    imageExplanation.textContent = data.explanation;
    clearList(imageReasons);
    data.reasons.forEach((reason) => {
      const li = document.createElement("li");
      li.textContent = reason;
      imageReasons.appendChild(li);
    });
    imageImpact.textContent = data.impact;
    showResult(imageResult);
  } catch (error) {
    alert(error.message);
  } finally {
    imageBtn.textContent = "Analyze Image";
    imageBtn.disabled = false;
  }
});
