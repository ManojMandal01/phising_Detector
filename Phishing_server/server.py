# from flask import Flask, request, jsonify
# import pandas as pd
# import re
# from urllib.parse import urlparse
# import ssl, socket
# import requests

# app = Flask(__name__)

# # ================================
# # Load Dataset
# # ================================
# df = pd.read_excel("data_bal - 20000.xlsx")
# df.columns = df.columns.str.lower()

# # Normalize URLs (add scheme if missing)
# def normalize_url(url):
#     if not url.startswith(("http://", "https://")):
#         url = "http://" + url
#     return url

# df["url"] = df["url"].apply(normalize_url)

# phishing_urls = set(df[df['label'] == 1]['url'])
# legit_urls = set(df[df['label'] == 0]['url'])

# # ================================
# # VirusTotal API Setup
# # ================================
# VT_API_KEY = "2e8f86a4d293fbc2ab68e3ed8035881190c89c4ddb9453a7d3e82bac1a7d5da9"
# VT_URL = "https://www.virustotal.com/vtapi/v2/url/report"

# # ================================
# # Suspicious Heuristics
# # ================================
# suspicious_keywords = [
#     "login", "verify", "secure", "update", "banking",
#     "account", "free", "bonus", "paypal", "gift"
# ]

# def check_ssl(domain):
#     """Check if domain has a valid SSL certificate."""
#     try:
#         ctx = ssl.create_default_context()
#         with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
#             s.settimeout(3)
#             s.connect((domain, 443))
#             cert = s.getpeercert()
#             return True if cert else False
#     except Exception:
#         return False

# def check_url_rules(url: str) -> str:
#     """Rule-based phishing detection."""
#     parsed = urlparse(url)
#     domain = parsed.netloc.lower()

#     # 1. SSL check (only for https)
#     if parsed.scheme == "https":
#         ssl_ok = check_ssl(domain)
#         if not ssl_ok:
#             return "suspicious"

#     # 2. If scheme is HTTP only
#     if parsed.scheme == "http":
#         return "suspicious"

#     # 3. Suspicious keywords in URL
#     for keyword in suspicious_keywords:
#         if keyword in url.lower():
#             return "suspicious"

#     # 4. Too many subdomains
#     if domain.count(".") > 3:
#         return "suspicious"

#     # 5. IP address as domain
#     if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
#         return "suspicious"

#     return "legit"

# def check_with_virustotal(url: str) -> str:
#     """Fallback: Check URL using VirusTotal API."""
#     try:
#         params = {"apikey": VT_API_KEY, "resource": url}
#         response = requests.get(VT_URL, params=params, timeout=10)
#         response_json = response.json()

#         if response_json.get("response_code") == 0:
#             return "unknown"
#         elif response_json.get("positives", 0) == 0:
#             return "legit"
#         else:
#             return "phishing"
#     except Exception as e:
#         print("VirusTotal check failed:", e)
#         return "unknown"

# # ================================
# # Flask Route
# # ================================
# @app.route('/check_url', methods=['POST'])
# def check_url():
#     data = request.get_json()
#     url = normalize_url(data.get("url", ""))

#     if not url:
#         return jsonify({"error": "No URL provided"}), 400

#     # Step 1: Dataset lookup
#     if url in phishing_urls:
#         verdict = "phishing"
#     elif url in legit_urls:
#         verdict = "legit"
#     else:
#         # Step 2: Rule-based heuristics
#         verdict = check_url_rules(url)

#         # Step 3: If verdict is still unclear/suspicious → VirusTotal
#         if verdict == "suspicious" or verdict == "unknown":
#             vt_verdict = check_with_virustotal(url)
#             if vt_verdict != "unknown":
#                 verdict = vt_verdict

#     return jsonify({"url": url, "verdict": verdict})

# # ================================
# # Run Server
# # ================================
# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=5000, debug=True)



# from flask import Flask, request, jsonify
# import pandas as pd
# import requests
# from urllib.parse import urlparse

# app = Flask(__name__)

# # --------------------------
# # 1. Load Dataset
# # --------------------------
# df = pd.read_excel("data_bal - 20000.xlsx")

# # Standardize column names
# df.columns = df.columns.str.strip().str.lower()
# # Now we have "labels" and "urls"

# def normalize_url(url):
#     url = url.strip().lower()
#     if url.startswith("http://"):
#         url = url.replace("http://", "https://", 1)
#     return url

# df["urls"] = df["urls"].apply(normalize_url)

# dataset_lookup = dict(zip(df["urls"], df["labels"]))

# # --------------------------
# # 2. Manual Rules
# # --------------------------
# def manual_rules(url):
#     parsed = urlparse(url)

#     # Rule 1: must use HTTPS
#     if parsed.scheme != "https":
#         return "suspicious"

#     # Rule 2: suspicious keywords
#     bad_keywords = ["login", "verify", "secure", "update", "bank", "paypal"]
#     if any(word in url.lower() for word in bad_keywords):
#         return "suspicious"

#     # Rule 3: very long domain
#     if len(parsed.netloc) > 40:
#         return "suspicious"

#     return "legitimate"

# # --------------------------
# # 3. VirusTotal Check
# # --------------------------
# VT_API_KEY = "2e8f86a4d293fbc2ab68e3ed8035881190c89c4ddb9453a7d3e82bac1a7d5da9"
# VT_URL = "https://www.virustotal.com/vtapi/v2/url/report"

# def virustotal_check(url):
#     params = {"apikey": VT_API_KEY, "resource": url}
#     try:
#         response = requests.get(VT_URL, params=params, timeout=10)
#         result = response.json()

#         if result.get("response_code") == 0:
#             return "unknown"
#         elif result.get("positives", 0) > 0:
#             return "malicious"
#         else:
#             return "legitimate"
#     except Exception as e:
#         print("VirusTotal error:", e)
#         return "error"

# # --------------------------
# # 4. Main Endpoint
# # --------------------------
# @app.route("/check_url", methods=["POST"])
# def check_url():
#     data = request.get_json()
#     url = data.get("url", "").strip()
#     if not url:
#         return jsonify({"error": "No URL provided"}), 400

#     url = normalize_url(url)

#     # Step 1: Dataset check
#     if url in dataset_lookup:
#         label = dataset_lookup[url]
#         return jsonify({
#             "url": url,
#             "verdict": "phishing" if label == 1 else "legitimate",
#             "source": "dataset"
#         })

#     # Step 2: Manual rules
#     manual_verdict = manual_rules(url)
#     if manual_verdict == "suspicious":
#         return jsonify({
#             "url": url,
#             "verdict": "suspicious",
#             "source": "manual_rules"
#         })

#     # Step 3: VirusTotal API
#     vt_verdict = virustotal_check(url)
#     return jsonify({
#         "url": url,
#         "verdict": vt_verdict,
#         "source": "virustotal"
#     })

# # --------------------------
# # Run Server
# # --------------------------
# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=5000, debug=True)






# from flask import Flask, request, jsonify
# from flask_cors import CORS
# import pandas as pd
# import requests
# from urllib.parse import urlparse

# app = Flask(__name__)
# CORS(app)  # <-- Enable Cross-Origin Requests for your extension

# # --------------------------
# # 1. Load Dataset
# # --------------------------
# df = pd.read_excel("data_bal - 20000.xlsx")

# # Standardize column names
# df.columns = df.columns.str.strip().str.lower()
# # Now we have "labels" and "urls"

# def normalize_url(url):
#     url = url.strip().lower()
#     if url.startswith("http://"):
#         url = url.replace("http://", "https://", 1)
#     return url

# df["urls"] = df["urls"].apply(normalize_url)
# dataset_lookup = dict(zip(df["urls"], df["labels"]))

# # --------------------------
# # 2. Manual Rules
# # --------------------------
# def manual_rules(url):
#     parsed = urlparse(url)

#     # Rule 1: must use HTTPS
#     if parsed.scheme != "https":
#         return "suspicious"

#     # Rule 2: suspicious keywords
#     bad_keywords = ["login", "verify", "secure", "update", "bank", "paypal"]
#     if any(word in url.lower() for word in bad_keywords):
#         return "suspicious"

#     # Rule 3: very long domain
#     if len(parsed.netloc) > 40:
#         return "suspicious"

#     return "legitimate"

# # --------------------------
# # 3. VirusTotal Check
# # --------------------------
# VT_API_KEY = "2e8f86a4d293fbc2ab68e3ed8035881190c89c4ddb9453a7d3e82bac1a7d5da9"
# VT_URL = "https://www.virustotal.com/vtapi/v2/url/report"

# def virustotal_check(url):
#     params = {"apikey": VT_API_KEY, "resource": url}
#     try:
#         response = requests.get(VT_URL, params=params, timeout=10)
#         result = response.json()

#         if result.get("response_code") == 0:
#             return "unknown"
#         elif result.get("positives", 0) > 0:
#             return "malicious"
#         else:
#             return "legitimate"
#     except Exception as e:
#         print("VirusTotal error:", e)
#         return "error"

# # --------------------------
# # 4. Main Endpoint
# # --------------------------
# @app.route("/check_url", methods=["POST"])
# def check_url():
#     data = request.get_json()
#     url = data.get("url", "").strip()
#     if not url:
#         return jsonify({"error": "No URL provided"}), 400

#     url = normalize_url(url)

#     # Step 1: Dataset check
#     if url in dataset_lookup:
#         label = dataset_lookup[url]
#         return jsonify({
#             "url": url,
#             "verdict": "phishing" if label == 1 else "legitimate",
#             "source": "dataset"
#         })

#     # Step 2: Manual rules
#     manual_verdict = manual_rules(url)
#     if manual_verdict == "suspicious":
#         return jsonify({
#             "url": url,
#             "verdict": "suspicious",
#             "source": "manual_rules"
#         })

#     # Step 3: VirusTotal API
#     vt_verdict = virustotal_check(url)
#     return jsonify({
#         "url": url,
#         "verdict": vt_verdict,
#         "source": "virustotal"
#     })

# # --------------------------
# # Run Server
# # --------------------------
# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=5000, debug=True)







from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import time
import pandas as pd
import requests
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)  # Enable CORS so extension content script can call server API

# Load Dataset
df = pd.read_excel("data_bal - 20000.xlsx")
df.columns = df.columns.str.strip().str.lower()

def _resolve_columns(frame):
    """Return the names for url and label columns, trying common variants.
    Raises a ValueError with a clear message if not found.
    """
    cols = set(frame.columns)
    url_candidates = ["urls", "url", "link", "website"]
    label_candidates = ["labels", "label", "target", "class"]

    url_col = next((c for c in url_candidates if c in cols), None)
    label_col = next((c for c in label_candidates if c in cols), None)

    if not url_col or not label_col:
        raise ValueError(
            f"Dataset must contain URL and label columns. Looked for {url_candidates} and {label_candidates}. Found columns: {sorted(cols)}"
        )
    return url_col, label_col

def normalize_url(url: str) -> str:
    """Normalize URL for matching without altering scheme aggressively.
    - strip whitespace
    - lowercase
    - remove trailing slash except when it's just scheme+host root
    """
    if not isinstance(url, str):
        return ""
    u = url.strip().lower()
    if not u:
        return u
    parsed = urlparse(u)
    # rebuild minimal normalized string: scheme://netloc + path
    path = parsed.path or ""
    # remove trailing slash if path length > 1
    if path.endswith("/") and len(path) > 1:
        path = path[:-1]
    rebuilt = f"{parsed.scheme}://{parsed.netloc}{path}"
    # keep query as part of identity if present
    if parsed.query:
        rebuilt += f"?{parsed.query}"
    return rebuilt

url_col, label_col = _resolve_columns(df)
df[url_col] = df[url_col].astype(str).apply(normalize_url)
dataset_lookup = dict(zip(df[url_col], df[label_col]))

def manual_rules(url):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return "suspicious"
    bad_keywords = ["login", "verify", "secure", "update", "bank", "paypal"]
    if any(word in url.lower() for word in bad_keywords):
        return "suspicious"
    if len(parsed.netloc) > 40:
        return "suspicious"
    return "legitimate"

VT_API_KEY = os.environ.get("VT_API_KEY")  # Read from environment for security
VT_URL = "https://www.virustotal.com/vtapi/v2/url/report"

# In-memory cache and simple rate limiting for VT to respect free tier limits
VT_CACHE_TTL = 24 * 60 * 60  # 24 hours
VT_RATE_LIMIT_PER_MIN = 3     # max VT calls per minute
_vt_cache = {}               # key: normalized url -> (verdict, timestamp)
_vt_window_start = 0.0
_vt_count = 0
_vt_cooldown_until = 0.0

def _vt_allowed_now():
    global _vt_window_start, _vt_count, _vt_cooldown_until
    now = time.time()
    # Respect cooldown (e.g., after 429s)
    if now < _vt_cooldown_until:
        return False
    if now - _vt_window_start >= 60:
        _vt_window_start = now
        _vt_count = 0
    return _vt_count < VT_RATE_LIMIT_PER_MIN

def _vt_record_call():
    global _vt_count
    _vt_count += 1

def virustotal_check(url):
    # Return cached verdict if fresh
    now = time.time()
    cached = _vt_cache.get(url)
    if cached and (now - cached[1]) < VT_CACHE_TTL:
        return cached[0]

    if not VT_API_KEY:
        print("VirusTotal API key not set. Set VT_API_KEY environment variable to enable VT checks.")
        return "unknown"

    if not _vt_allowed_now():
        # Over budget; skip VT query to avoid 429s
        return "unknown"

    params = {"apikey": VT_API_KEY, "resource": url}
    try:
        _vt_record_call()
        response = requests.get(VT_URL, params=params, timeout=5)
        # Handle rate limiting explicitly
        if response.status_code == 429:
            # Enter short cooldown to avoid hammering
            global _vt_cooldown_until
            _vt_cooldown_until = time.time() + 60  # 1 minute cooldown
            return "unknown"

        response.raise_for_status()
        result = response.json()
        if result.get("response_code") == 0:
            verdict = "unknown"
        elif result.get("positives", 0) > 0:
            verdict = "malicious"
        else:
            verdict = "legitimate"
        _vt_cache[url] = (verdict, now)
        return verdict
    except Exception as e:
        print("VirusTotal error:", e)
        return "error"

@app.route("/check_url", methods=["POST"])
def check_url():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    url = normalize_url(url)

    if url in dataset_lookup:
        label = dataset_lookup[url]
        return jsonify({
            "url": url,
            "verdict": "phishing" if label == 1 else "legitimate",
            "source": "dataset"
        })

    manual_verdict = manual_rules(url)
    if manual_verdict == "suspicious":
        # For suspicious URLs, consult VirusTotal to get a decisive verdict
        vt_verdict = virustotal_check(url)
        if vt_verdict in ("malicious", "legitimate"):
            return jsonify({
                "url": url,
                "verdict": vt_verdict,
                "source": "virustotal"
            })
        # If VT is unknown/error, fall back to manual suspicious
        return jsonify({
            "url": url,
            "verdict": "suspicious",
            "source": "manual_rules"
        })

    # Balanced profile: if manual rules consider it legitimate, skip VT to save quota/latency
    return jsonify({
        "url": url,
        "verdict": "legitimate",
        "source": "manual_rules"
    })

if __name__ == "__main__":
    # Run with HTTPS for browser compatibility
    app.run(host="0.0.0.0", port=5000, debug=True)
