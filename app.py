from flask import Flask, render_template, request
import re
from urllib.parse import urlparse
from ipaddress import ip_address

app = Flask(__name__)

EMAIL_FLAGS = ["verify your account", "account will be suspended", "urgent action required",
               "reset your password", "confirm your password", "click here immediately",
               "claim your prize", "unusual activity", "payment failed"]
SENSITIVE_FLAGS = ["password", "login details", "credit card", "bank account", "one-time password", "otp"]
URL_FLAGS = ["login", "verify", "secure", "account", "update", "password", "confirm", "wallet", "banking", "signin"]

def extract_urls(text):
    return [u.rstrip(".,!?;:)]}") for u in re.findall(r"""https?://[^\s<>"']+|www\.[^\s<>"']+""", text, re.I)]

def analyze_url(url):
    original = url.strip()
    candidate = "http://" + original if original.lower().startswith("www.") else original
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    score, reasons = 0, []
    if not host:
        return {"score": 0, "verdict": "Needs review", "reasons": ["Could not identify a valid hostname."]}
    if parsed.scheme != "https":
        score += 1
        reasons.append("URL does not use HTTPS; this alone does not prove phishing.")
    if "@" in parsed.netloc:
        score += 3
        reasons.append("Contains '@' in the network location, which can disguise the destination.")
    try:
        ip_address(host)
        score += 3
        reasons.append("Uses an IP address instead of a regular domain name.")
    except ValueError:
        pass
    if host.startswith("xn--") or ".xn--" in host:
        score += 2
        reasons.append("Contains a punycode domain label that may hide look-alike characters.")
    if len(original) > 100:
        score += 1
        reasons.append("Unusually long URL.")
    if host.count("-") >= 3:
        score += 1
        reasons.append("Domain contains several hyphens.")
    if host.count(".") >= 4:
        score += 1
        reasons.append("Hostname has many subdomain levels; inspect the registered domain carefully.")
    words = [w for w in URL_FLAGS if w in original.lower()]
    if words:
        score += 1
        reasons.append("Contains account-related URL words: " + ", ".join(words) + ".")
    if not reasons:
        reasons.append("No listed warning patterns were found; still verify the domain and context.")
    verdict = "Suspicious" if score >= 4 else "Needs review" if score >= 2 else "Lower risk based on these simple rules"
    return {"score": score, "verdict": verdict, "reasons": reasons}

def analyze_email(text):
    low = text.lower()
    score, reasons = 0, []
    for phrase in EMAIL_FLAGS:
        if phrase in low:
            score += 1
            reasons.append(f"Urgent or pressure-based phrase: '{phrase}'.")
    hits = [w for w in SENSITIVE_FLAGS if w in low]
    if hits:
        score += min(2, len(hits))
        reasons.append("Mentions sensitive information: " + ", ".join(hits) + ".")
    urls = extract_urls(text)
    if urls:
        reasons.append(f"Found {len(urls)} URL(s) to inspect.")
        for url in urls:
            result = analyze_url(url)
            if result["score"] >= 2:
                score += 2
                reasons.append(f"URL needs attention: {url} ({result['verdict']}).")
    else:
        reasons.append("No URL-like strings were found in the email text.")
    verdict = "Suspicious" if score >= 4 else "Needs review" if score >= 2 else "Lower risk based on these simple rules"
    return {"score": score, "verdict": verdict, "reasons": reasons, "urls": urls}

@app.route("/", methods=["GET", "POST"])
def index():
    result, mode, user_input = None, "email", ""
    if request.method == "POST":
        mode = request.form.get("mode", "email")
        user_input = request.form.get("user_input", "").strip()
        if mode == "simulation":
            user_input = "Urgent action required: verify your account at http://198.51.100.24/verify"
            result = analyze_email(user_input)
            result["kind"] = "Safe phishing-awareness simulation"
        elif mode == "email" and user_input:
            result = analyze_email(user_input)
            result["kind"] = "Email analysis"
        elif mode == "url" and user_input:
            result = analyze_url(user_input)
            result["kind"] = "URL analysis"
        else:
            result = {"kind": "Input required", "verdict": "No input", "score": 0,
                      "reasons": ["Please enter email text or a URL before analyzing."]}
    return render_template("index.html", result=result, mode=mode, user_input=user_input)

if __name__ == "__main__":
    # Local-only demo server. Do not expose this development server to the internet.
    app.run(host="127.0.0.1", port=5000, debug=False)
