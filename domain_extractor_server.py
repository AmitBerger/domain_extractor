from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
import os
import tempfile
from domain_extractor import (
    extract_domains,
    get_domain_ip,
    check_domain_virustotal,
    get_asn_info,
)
import requests
from typing import Optional

app = Flask(__name__)
CORS(app)

# Load VirusTotal API key from environment
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
if not VT_API_KEY:
    print(
        "Warning: 'VIRUSTOTAL_API_KEY' environment variable not set. Skipping VirusTotal checks."
    )


def process_domains(text, vt_api_key=None, check_vt=True):
    """Extract and resolve domains using domain_extractor.py functions"""
    domains = extract_domains(text)
    results = []

    for domain in domains:
        ip = get_domain_ip(domain)
        vt_status = (
            check_domain_virustotal(domain, vt_api_key)
            if (vt_api_key and check_vt)
            else None
        )
        asn_info = get_asn_info(ip) if ip else None

        # Optionally, parse ASN info into a dict for easier frontend use
        asn_dict = {}
        if asn_info:
            for part in asn_info.split(" | "):
                if ":" in part:
                    k, v = part.split(":", 1)
                    asn_dict[k] = v
                else:
                    asn_dict["AS"] = part

        results.append(
            {
                "domain": domain,
                "status": "resolved" if ip else "valid",
                "ip": ip,
                "id": domain.replace(".", "_"),
                "vt_status": vt_status,
                "asn_info": asn_dict or None,
            }
        )

    return results


@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/api/extract", methods=["POST"])
def extract_domains_api():
    try:
        data = request.get_json()
        text = data.get("text", "")
        check_vt = data.get("checkVirusTotal", True)
        vt_api_key = data.get("virustotal_api_key")
        if not text:
            return jsonify({"error": "No text provided"}), 400

        results = process_domains(text, vt_api_key, check_vt)
        return jsonify(
            {
                "success": True,
                "results": results,
                "stats": {
                    "total": len(results),
                    "resolved": len([r for r in results if r["ip"]]),
                    "valid": len([r for r in results if not r["ip"]]),
                },
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/extract-file", methods=["POST"])
def extract_from_file():
    try:
        vt_api_key = request.form.get("virustotal_api_key")
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400

        text = file.read().decode("utf-8")
        results = process_domains(text, vt_api_key)

        return jsonify(
            {
                "success": True,
                "results": results,
                "stats": {
                    "total": len(results),
                    "resolved": len([r for r in results if r["ip"]]),
                    "valid": len([r for r in results if not r["ip"]]),
                },
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/download", methods=["POST"])
def download_results():
    try:
        data = request.get_json()
        results = data.get("results", [])

        # Compose lines like the CLI output.txt
        lines = []
        for r in results:
            line_parts = [r["domain"]]
            if r.get("ip"):
                line_parts.append(r["ip"])
            if r.get("vt_status"):
                line_parts.append(f"VT:{r['vt_status']}")
            if r.get("asn_info"):
                # Join ASN info as a single string, like output.txt
                asn_str = "ASN:" + " | ".join(
                    f"{k}:{v}" if k != "AS" else v for k, v in r["asn_info"].items()
                )
                line_parts.append(asn_str)
            # Only join non-empty parts
            line = " ".join(part for part in line_parts if part)
            lines.append(line)

        content = "\n".join(lines)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write(content)
            temp_path = f.name

        return send_from_directory(
            os.path.dirname(temp_path),
            os.path.basename(temp_path),
            as_attachment=True,
            download_name="extracted_domains.txt",
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/download-output", methods=["GET"])
def download_output_txt():
    output_path = "output.txt"
    if not os.path.exists(output_path):
        return jsonify({"error": "No output.txt file found"}), 404
    return send_file(output_path, as_attachment=True, download_name="output.txt")


if __name__ == "__main__":
    print("🚀 Domain Extractor Server running on http://localhost:5000")
    app.run(debug=True, port=5000)
