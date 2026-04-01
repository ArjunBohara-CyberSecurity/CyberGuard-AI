import io
import os
from datetime import datetime
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException


APP_NAME = "CyberGuardAI"
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gemma3:1b")

SCAM_KEYWORDS = {
    "login": 10,
    "verify": 12,
    "urgent": 14,
    "free": 8,
    "win": 10,
    "password": 12,
    "bank": 12,
    "account": 8,
    "limited": 10,
    "alert": 8,
    "security": 6,
    "confirm": 8,
    "update": 8,
    "click": 10,
    "gift": 10,
    "prize": 10,
    "refund": 10,
}

URGENCY_PHRASES = [
    "act now",
    "immediately",
    "last chance",
    "urgent",
    "final notice",
    "limited time",
]

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "xyz",
    "top",
    "click",
    "work",
    "country",
}

COMMON_BRANDS = {
    "microsoft",
    "google",
    "paypal",
    "facebook",
    "apple",
    "amazon",
    "instagram",
    "bank",
}


def create_app():
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template(
            "index.html",
            year=datetime.now().year,
            model_name=OLLAMA_MODEL,
        )

    @app.route("/api/scan-text", methods=["POST"])
    def scan_text():
        data = request.get_json(silent=True) or {}
        text = (data.get("text") or "").strip()
        if not text:
            return jsonify({"error": "Please enter a message or link to scan."}), 400

        analysis = analyze_text(text)
        explanation = generate_explanation(
            kind="text",
            label=analysis["risk_level"],
            score=analysis["confidence"],
            reasons=analysis["reasons"],
        )
        analysis["explanation"] = explanation
        return jsonify(analysis)

    @app.route("/api/scan-image", methods=["POST"])
    def scan_image():
        if "image" not in request.files:
            return jsonify({"error": "Please upload an image."}), 400
        file = request.files["image"]
        if not file or file.filename == "":
            return jsonify({"error": "Please upload an image."}), 400

        try:
            from PIL import Image

            raw = file.read()
            image = Image.open(io.BytesIO(raw)).convert("RGB")
        except Exception:
            return jsonify({"error": "Unsupported image format."}), 400

        analysis = analyze_image(image)
        explanation = generate_explanation(
            kind="image",
            label=analysis["label"],
            score=analysis["confidence"],
            reasons=analysis["reasons"],
        )
        analysis["explanation"] = explanation
        return jsonify(analysis)

    @app.errorhandler(Exception)
    def handle_error(err):
        if request.path.startswith("/api/"):
            code = err.code if isinstance(err, HTTPException) else 500
            return jsonify({"error": str(err)}), code
        raise err

    return app


def analyze_text(text):
    lowered = text.lower()
    score = 0
    reasons = []
    is_single_url = is_probably_single_url(text)

    keyword_hits = []
    for word, weight in SCAM_KEYWORDS.items():
        if word in lowered:
            score += weight
            keyword_hits.append(word)

    if keyword_hits:
        reasons.append(f"Scam-style keywords detected: {', '.join(keyword_hits[:5])}.")

    for phrase in URGENCY_PHRASES:
        if phrase in lowered:
            score += 10
            reasons.append("Urgency-based language detected.")
            break

    digit_ratio = sum(ch.isdigit() for ch in text) / max(len(text), 1)
    symbol_ratio = sum(not ch.isalnum() and not ch.isspace() for ch in text) / max(len(text), 1)
    if not is_single_url and digit_ratio > 0.18:
        score += 10
        reasons.append("Too many numbers for a normal message.")
    if not is_single_url and symbol_ratio > 0.12:
        score += 10
        reasons.append("Too many symbols for a normal message.")

    url_risk, url_reason = assess_url_risk(text)
    if url_risk > 0:
        score += url_risk
        reasons.append(url_reason)

    ai_signal = ai_phishing_signal(text)
    if ai_signal:
        if ai_signal["verdict"] == "phishing":
            score += int(20 * ai_signal["confidence"])
            reasons.append("Local AI flagged this as a likely phishing link/message.")
        elif ai_signal["verdict"] == "safe":
            score -= int(8 * ai_signal["confidence"])
            reasons.append("Local AI found it likely safe, but logic checks still apply.")

    score = min(score, 100)
    risk_level = "SAFE"
    if score >= 65:
        risk_level = "DANGEROUS"
    elif score >= 30:
        risk_level = "SUSPICIOUS"

    if risk_level == "SAFE":
        confidence = min(90, 70 + int(max(0, 30 - score) * 0.5))
    else:
        confidence = min(max(score, 30), 98)
    impact = pick_impact(risk_level, kind="text")

    if not reasons or risk_level == "SAFE":
        reasons = ["No obvious scam patterns found."]

    return {
        "risk_level": risk_level,
        "confidence": confidence,
        "reasons": reasons,
        "impact": impact,
    }


def assess_url_risk(text):
    import re

    url_matches = re.findall(r"(https?://[^\s]+|www\.[^\s]+)", text, flags=re.IGNORECASE)
    if not url_matches:
        return 0, "No obvious link patterns found."

    url = url_matches[0].strip("()[]<>.,")
    if url.startswith("www."):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        return 8, "Link looks incomplete or malformed."

    safe_domains = {
        "google.com",
        "www.google.com",
        "microsoft.com",
        "www.microsoft.com",
        "apple.com",
        "www.apple.com",
        "amazon.com",
        "www.amazon.com",
    }
    if host in safe_domains and len(url_matches) == 1:
        return 0, "Recognized major domain."

    score = 0
    if host.replace(".", "").isdigit():
        score += 20
        return score, "Link uses a raw IP address (common in scams)."

    if "xn--" in host:
        score += 20
        return score, "Link contains punycode (can hide lookalike domains)."

    parts = host.split(".")
    if len(parts) >= 4:
        score += 8
        reason = "Too many subdomains for a normal site."
    else:
        reason = "Link looks structurally normal."

    tld = parts[-1] if parts else ""
    if tld in SUSPICIOUS_TLDS:
        score += 10
        reason = "Uncommon or risky domain ending detected."

    if len(host) > 28:
        score += 6
        reason = "Link is unusually long."

    if sum(ch.isdigit() for ch in host) > 3:
        score += 6
        reason = "Link has a suspicious amount of numbers."

    if host.count("-") >= 2:
        score += 6
        reason = "Multiple dashes in the domain can be suspicious."

    if is_lookalike_brand(host):
        score += 30
        reason = "Link resembles a known brand but looks slightly altered."

    return score, reason


def is_lookalike_brand(host):
    base = host.split(".")[0]
    normalized = base
    normalized = normalized.replace("0", "o").replace("1", "l").replace("3", "e").replace("5", "s").replace("7", "t")
    normalized = normalized.replace("rn", "m").replace("vv", "w")
    for brand in COMMON_BRANDS:
        if brand in normalized and brand not in base:
            return True
    return False


def is_probably_single_url(text):
    stripped = text.strip()
    return (
        stripped.startswith("http://")
        or stripped.startswith("https://")
        or stripped.startswith("www.")
    ) and len(stripped.split()) == 1


def analyze_image(image):
    import numpy as np

    arr = np.array(image).astype(np.float32)
    gray = np.mean(arr, axis=2)

    gx = np.diff(gray, axis=1)
    gy = np.diff(gray, axis=0)
    sharpness = float(np.var(gx) + np.var(gy))

    left = np.mean(gray[:, : gray.shape[1] // 2])
    right = np.mean(gray[:, gray.shape[1] // 2 :])
    top = np.mean(gray[: gray.shape[0] // 2, :])
    bottom = np.mean(gray[gray.shape[0] // 2 :, :])

    lighting_gap = max(abs(left - right), abs(top - bottom))

    min_h = min(gx.shape[0], gy.shape[0])
    min_w = min(gx.shape[1], gy.shape[1])
    edges = np.hypot(gx[:min_h, :min_w], gy[:min_h, :min_w])
    edge_density = float(np.mean(edges > 20))

    h, w = gray.shape
    border_band = max(4, min(12, min(h, w) // 4))
    border = np.concatenate(
        [
            gray[:border_band, :].ravel(),
            gray[-border_band:, :].ravel(),
            gray[:, :border_band].ravel(),
            gray[:, -border_band:].ravel(),
        ]
    )
    center = gray[border_band:-border_band, border_band:-border_band].ravel()
    if center.size == 0:
        border_contrast = 0
    else:
        border_contrast = abs(float(np.mean(border) - np.mean(center)))

    score = 0
    reasons = []

    if sharpness < 80:
        score += 25
        reasons.append("Blurry or overly smooth textures detected.")

    if lighting_gap > 18:
        score += 20
        reasons.append("Lighting looks uneven across the face area.")

    if edge_density > 0.18:
        score += 15
        reasons.append("Unnatural edge artifacts detected.")

    if border_contrast > 18:
        score += 10
        reasons.append("Edges look inconsistent compared to the center.")

    score = min(score, 100)

    label = "REAL"
    if score >= 65:
        label = "FAKE"
    elif score >= 35:
        label = "POSSIBLY FAKE"

    if label == "REAL":
        confidence = min(90, 70 + int(max(0, 30 - score) * 0.5))
    else:
        confidence = min(max(score, 30), 98)
    impact = pick_impact(label, kind="image")

    if not reasons:
        reasons.append("No strong deepfake patterns were detected.")

    return {
        "label": label,
        "confidence": confidence,
        "reasons": reasons,
        "impact": impact,
    }


def pick_impact(label, kind):
    if kind == "text":
        if label == "DANGEROUS":
            return "This could lead to account theft or financial fraud."
        if label == "SUSPICIOUS":
            return "This could be used in phishing or impersonation scams."
        return "Looks safe, but always double-check links before clicking."
    if label == "FAKE":
        return "Fake images can spread misinformation quickly."
    if label == "POSSIBLY FAKE":
        return "This could be used to manipulate trust or identity."
    return "Looks genuine, but stay cautious with viral content."


def generate_explanation(kind, label, score, reasons):
    prompt = (
        "You are CyberGuardAI, a beginner-friendly safety assistant. "
        "Explain the scan result in 1-2 short sentences with no jargon. "
        f"Result: {label}. Confidence: {score}%. "
        f"Reasons: {', '.join(reasons)}"
    )

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2},
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=8)
        if response.ok and "application/json" in response.headers.get("Content-Type", ""):
            data = response.json()
            text = (data.get("response") or "").strip()
            if text:
                return text
    except Exception:
        pass

    # Fallback explanation if local AI is unavailable
    if kind == "text":
        return f"This message looks {label.lower()} because {reasons[0].lower()}"
    return f"This image looks {label.lower()} because {reasons[0].lower()}"


def ai_phishing_signal(text):
    prompt = (
        "You are a safety classifier. Decide if the text is phishing or safe. "
        "Return ONLY valid JSON with keys: verdict (phishing|safe) and confidence (0-1). "
        f"Text: {text}"
    )
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.0},
    }
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=8)
        if not response.ok:
            return None
        raw = (response.json().get("response") or "").strip()
        if not raw:
            return None
        # Extract JSON object even if the model adds extra text
        import re

        match = re.search(r"\{.*\}", raw, flags=re.DOTALL)
        if not match:
            return None
        data = json.loads(match.group(0))
        verdict = str(data.get("verdict", "")).lower()
        confidence = float(data.get("confidence", 0))
        if verdict not in {"phishing", "safe"}:
            return None
        confidence = max(0.0, min(confidence, 1.0))
        return {"verdict": verdict, "confidence": confidence}
    except Exception:
        return None


if __name__ == "__main__":
    app = create_app()
    try:
        from waitress import serve

        print(
            r"""
  _                __                      ___ 
 /     |_   _  ._ /__      __ ._ _|    /\   |  
 \_ \/ |_) (/_ |  \_| |_| (_| | (_|   /--\ _|_ 
    /                                          
"""
        )
        print("CyberGuardAI running at http://127.0.0.1:5000")
        serve(app, host="127.0.0.1", port=5000)
    except Exception:
        print(
            r"""
  ____        _               ____                 _      ___ 
 / ___| _   _| |__   ___ _ __/ ___|_   _  __ _ _ __| | ___|_ _|
| |    | | | | '_ \ / _ \ '__| |  _| | | |/ _` | '__| |/ / | | 
| |___ | |_| | |_) |  __/ |  | |_| | |_| | (_| | |  |   <  | | 
 \____| \__,_|_.__/ \___|_|   \____|\__,_|\__,_|_|  |_|\_\|___|
                      CyberGuard AI
"""
        )
        print("CyberGuardAI running at http://127.0.0.1:5000")
        app.run(debug=False)
