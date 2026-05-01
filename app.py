from flask import Flask, jsonify, render_template
import subprocess
import re

app = Flask(__name__)

# ─── Demo data (always works, no real scan needed) ───────────────────────────
# NEW: Added "signal" field (percentage) to each demo entry
DEMO_NETWORKS = [
    {"ssid": "Home_Network",  "security": "WPA2", "signal": 85},
    {"ssid": "Cafe_Wifi",     "security": "Open", "signal": 60},
    {"ssid": "Free_Wifi",     "security": "Open", "signal": 45},
    {"ssid": "Free_Wifi",     "security": "Open", "signal": 50},   # duplicate → SUSPICIOUS
    {"ssid": "Office_Net",    "security": "WPA3", "signal": 78},
    {"ssid": "PublicHotspot", "security": "Open", "signal": 30},
]

def get_status(ssid, security, ssid_counts):
    """Decide SAFE / UNSAFE / SUSPICIOUS."""
    if ssid_counts[ssid] > 1:
        return "SUSPICIOUS"
    if security.lower() == "open":
        return "UNSAFE"
    return "SAFE"

# NEW: Classify signal percentage into High / Medium / Low
def get_signal_label(signal):
    """Return signal quality label based on percentage."""
    if signal >= 70:
        return "High"
    elif signal >= 40:
        return "Medium"
    else:
        return "Low"

def parse_networks(raw_output):
    """Pull SSIDs, Authentication, and Signal from netsh output."""
    networks = []
    current = {}

    for line in raw_output.splitlines():
        line = line.strip()

        # New network block starts with SSID number
        ssid_match = re.match(r'^SSID\s+\d+\s*:\s*(.+)$', line)
        if ssid_match:
            if current.get("ssid") and current.get("security"):
                networks.append(current)
            current = {"ssid": ssid_match.group(1).strip()}

        # Authentication line
        auth_match = re.match(r'^Authentication\s*:\s*(.+)$', line)
        if auth_match and current.get("ssid"):
            auth = auth_match.group(1).strip()
            # Simplify to Open / WPA2 / WPA3
            if "WPA3" in auth:
                current["security"] = "WPA3"
            elif "WPA2" in auth or "WPA-2" in auth:
                current["security"] = "WPA2"
            elif "Open" in auth:
                current["security"] = "Open"
            else:
                current["security"] = auth  # keep raw value

        # NEW: Extract Signal percentage (e.g. "Signal : 78%")
        signal_match = re.match(r'^Signal\s*:\s*(\d+)%', line)
        if signal_match and current.get("ssid"):
            current["signal"] = int(signal_match.group(1))

    # Don't forget the last block
    if current.get("ssid") and current.get("security"):
        networks.append(current)

    return networks

def annotate(networks):
    """Add status, detection count, signal strength, risk score, risk level, and warning."""
    from collections import Counter
    ssid_counts = Counter(n["ssid"] for n in networks)
    result = []
    for n in networks:
        signal_val = n.get("signal", 0)

        # ── Risk Score calculation (0–100) ────────────────────────────────────
        # Each factor adds points — higher score = more dangerous
        score = 0
        if n["security"].lower() == "open":   score += 50  # No encryption → big risk
        if ssid_counts[n["ssid"]] > 1:        score += 30  # Duplicate SSID → possible Evil Twin
        if signal_val < 40:                   score += 20  # Weak signal → suspicious/unstable
        score = min(score, 100)                            # Cap at 100

        # ── Risk Level based on score ─────────────────────────────────────────
        if score <= 30:
            risk_level   = "LOW"
            warning      = "Safe to use"
        elif score <= 70:
            risk_level   = "MEDIUM"
            warning      = "Use cautiously"
        else:
            risk_level   = "HIGH"
            warning      = "Avoid connecting"

        result.append({
            "ssid":         n["ssid"],
            "security":     n["security"],
            "status":       get_status(n["ssid"], n["security"], ssid_counts),
            "count":        ssid_counts[n["ssid"]],
            "signal":       signal_val,
            "signal_label": get_signal_label(signal_val),
            "risk_score":   score,       # NEW: numeric risk score
            "risk_level":   risk_level,  # NEW: LOW / MEDIUM / HIGH
            "warning":      warning,     # NEW: human-readable advice
        })

    # ── Sort safest first (lowest risk score first) ───────────────────────────
    result.sort(key=lambda x: x["risk_score"])

    # ── Recommend the best network (first SAFE + High signal + not duplicate) ─
    recommended = None
    for net in result:
        if net["status"] == "SAFE" and net["count"] == 1 and net["signal"] >= 70:
            recommended = net["ssid"]
            break
    # If none meet all criteria, pick the lowest risk score one
    if not recommended and result:
        recommended = result[0]["ssid"]

    # Tag the recommended network
    for net in result:
        net["recommended"] = (net["ssid"] == recommended)

    return result

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan")
def scan():
    """Run real netsh scan (Windows only)."""
    try:
        output = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            encoding="utf-8", errors="ignore",
            timeout=10
        )
        networks = parse_networks(output)
        if not networks:
            return jsonify({"error": "No networks found. Are you on Windows with Wi-Fi enabled?"}), 400
        return jsonify(annotate(networks))
    except FileNotFoundError:
        return jsonify({"error": "netsh not found. This scan only works on Windows."}), 400
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Scan timed out. Try again."}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/demo")
def demo():
    """Return hardcoded demo data."""
    return jsonify(annotate(DEMO_NETWORKS))

# NEW: Connect to a Wi-Fi network by SSID name
@app.route("/connect/<path:ssid>")
def connect(ssid):
    """Run netsh wlan connect to join the given Wi-Fi network."""
    try:
        result = subprocess.check_output(
            ["netsh", "wlan", "connect", f"name={ssid}"],
            encoding="utf-8", errors="ignore",
            timeout=10
        )
        # netsh returns "Connection request was completed successfully."
        if "successfully" in result.lower():
            return jsonify({"success": True,  "message": f"Connected to '{ssid}' successfully!"})
        else:
            return jsonify({"success": False, "message": result.strip()})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "Connection timed out. Try again."}), 500
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# ─── Run ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True)