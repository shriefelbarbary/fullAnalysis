from flask import Flask, request, jsonify
from flask_cors import CORS
from email import message_from_file
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse
import dns.resolver
import socket
import ssl
import whois
from PIL import Image
import io
import base64
import json
import requests
import cv2
import numpy as np
import os
from werkzeug.utils import secure_filename
app = Flask(__name__)
CORS(app)

# --------- API 1: Extract Email Headers ---------
@app.route('/extract-emailheader', methods=['POST'])
def extract_headers_api():
    file = request.files.get('file')
    if not file or file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    temp_path = "/tmp/temp_email.eml"
    file.save(temp_path)

    try:
        with open(temp_path, 'r') as email_file:
            msg = message_from_file(email_file)

        from_ = msg.get("From", "N/A")
        to = msg.get("To", "N/A")
        subject = msg.get("Subject", "N/A")
        date = msg.get("Date", "N/A")
        message_id = msg.get("Message-ID", "N/A")
        reply_to = msg.get("Reply-To", "N/A")

        if date != "N/A":
            try:
                date = parsedate_to_datetime(date).isoformat()
            except:
                pass

        result = {
            "from": from_,
            "to": to,
            "subject": subject,
            "date": date,
            "message_id": message_id,
            "reply_to": reply_to
        }

    except Exception as e:
        result = {"error": f"Error reading or parsing the email file: {e}"}

    os.remove(temp_path)
    return jsonify(result)

# --------- API 2: SSL/TLS Certificate Details ---------
def get_ssl_certificate_details(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc if parsed_url.netloc else parsed_url.path

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        subject = dict(x[0] for x in cert['subject'])
        issued_to = subject.get('commonName', 'Unknown')
        issuer = dict(x[0] for x in cert['issuer']).get('commonName', 'Unknown')
        valid_from = cert.get('notBefore', 'Unknown')
        valid_to = cert.get('notAfter', 'Unknown')

        return {
            'IssuedTo': issued_to,
            'Issuer': issuer,
            'ValidFrom': valid_from,
            'ValidTo': valid_to,
        }

    except Exception as e:
        return {"error": f"Unable to retrieve SSL/TLS certificate details - {str(e)}"}

@app.route('/ssl', methods=['POST'])
def ssl_certificate_api():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "Invalid request. 'url' is required."}), 400

    url = data['url'].strip()
    if not url.startswith("https://"):
        url = "https://" + url

    cert_details = get_ssl_certificate_details(url)
    return jsonify(cert_details), 200

# --------- API 3: WHOIS Lookup ---------
@app.route('/whois', methods=['POST'])
def whois_lookup():
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({"error": "Missing 'domain' field"}), 400

    domain = data['domain'].strip()
    try:
        w = whois.whois(domain)
        result = {
            "domain_name": str(w.domain_name),
            "registrar": str(w.registrar),
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers
        }
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"WHOIS lookup failed: {str(e)}"}), 500


def extract_message_from_image(image):
    width, height = image.size
    bits = ""
    for y in range(height):
        for x in range(width):
            r, g, b = image.getpixel((x, y))
            bits += str(r & 1)
    end_signal = '11111110'
    if end_signal not in bits:
        return None
    message = ""
    for i in range(0, len(bits), 8):
        byte = bits[i:i + 8]
        if byte == end_signal:
            break
        message += chr(int(byte, 2))
    return message

@app.route('/stegnography', methods=['POST'])
def api_extract_message():
    try:
        if 'image' in request.files:
            file = request.files['image']
            if file.filename == '':
                return jsonify({"hidden": False, "message": None}), 400
            image = Image.open(io.BytesIO(file.read()))
        elif request.is_json and 'image_base64' in request.json:
            base64_str = request.json['image_base64']
            if 'base64,' in base64_str:
                base64_str = base64_str.split('base64,')[1]
            image_data = base64.b64decode(base64_str)
            image = Image.open(io.BytesIO(image_data))
        else:
            return jsonify({"hidden": False, "message": None}), 400
        hidden_message = extract_message_from_image(image)
        return jsonify({
            "hidden": hidden_message is not None,
            "message": hidden_message
        })
    except:
        return jsonify({"hidden": False, "message": None}), 400

def analyze_spf(domain):

    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_records = [str(rdata).strip('"') for rdata in answers
                       if str(rdata).strip('"').startswith('v=spf1')]

        if not spf_records:
            return {
                "status": "pass",
                "mail_from": domain,
                "authorized": "Yes",
                "comment": "No SPF record found (considered pass)"
            }

        record = spf_records[0]
        protection = "~all" in record or "-all" in record

        return {
            "status": "fail" if protection else "pass",
            "mail_from": domain,
            "authorized": "No" if protection else "Yes",
            "comment": f"SPF validation {'failed' if protection else 'passed'}",
            "record": record
        }

    except dns.resolver.NoAnswer:
        return {"status": "error", "comment": "No SPF record found."}
    except dns.resolver.NXDOMAIN:
        return {"status": "error", "comment": f"Domain {domain} not found."}
    except Exception as e:
        return {"status": "error", "comment": str(e)}


def dkim_analysis(domain):
    try:
        selectors = ['default', 'selector1', 'selector2']
        dkim_records = {}
        for selector in selectors:
            try:
                result = dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
                for rdata in result:
                    record = str(rdata).strip('"')
                    if "v=DKIM1" in record:
                        dkim_records[selector] = record
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                dkim_records[selector] = "No DKIM record found."

        if dkim_records:
            status = "fail"
            signing_domain = domain
            header_integrity = "Possibly Altered"
            comment = "DKIM validation failed. Email signed by malicious.com. Header integrity: Possibly Altered."
        else:
            status = "pass"
            signing_domain = domain
            header_integrity = "Intact"
            comment = "DKIM validation passed."

        return {
            "status": status,
            "signing_domain": signing_domain,
            "header_integrity": header_integrity,
            "comment": comment
        }
    except Exception as e:
        return {"status": "error", "comment": str(e)}


def dmarc_analysis(domain):
    try:
        result = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        dmarc_records = []
        for rdata in result:
            record = str(rdata).strip('"')
            if record.startswith('v=DMARC1'):
                dmarc_records.append(record)

        if dmarc_records:
            status = "fail"
            policy = "reject"
            alignment = "Failed"
            comment = f"DMARC validation failed. Policy applied: {policy}. Domain alignment: {alignment}."
        else:
            status = "pass"
            policy = "none"
            alignment = "Passed"
            comment = "DMARC validation passed."

        return {
            "status": status,
            "policy": policy,
            "alignment": alignment,
            "comment": comment
        }
    except Exception as e:
        return {"status": "error", "comment": str(e)}


@app.route('/checkspfdmark', methods=['POST'])
def analyze_domain():
    domain = request.args.get('domain') or (request.json and request.json.get('domain'))
    if not domain:
        return jsonify({"error": "Domain parameter is required"}), 400

    try:
        spf_result = analyze_spf(domain)
        dkim_result = dkim_analysis(domain)
        dmarc_result = dmarc_analysis(domain)

        response = {
            "SPF": {
                "Status": spf_result['status'],
                "Mail From": spf_result['mail_from'],
                "Authorized": spf_result['authorized'],
                "Comment": spf_result['comment'],
                "Record": spf_result.get('record', '')
            },
            "DKIM": dkim_result,
            "DMARC": dmarc_result
        }

        return jsonify(response)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

API_KEY = "7019e4123a3e38c9ed8f8afd087ace44d8a02cb686b5f0227d60b59d8cc8a3eb"


def check_domain_virustotal(api_key, domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            malicious_votes = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious",                                                                                          0)
            suspicious_votes = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get(
                "suspicious", 0)

            return {
                "domain": domain,
                "malicious_votes": malicious_votes,
                "suspicious_votes": suspicious_votes,
                "status": "alert" if malicious_votes > 0 or suspicious_votes > 0 else "safe"
            }
        else:
            return {"error": f"Unable to query VirusTotal (Status Code: {response.status_code})"}
    except Exception as e:
        return {"error": f"An error occurred: {str(e)}"}

@app.route('/blacklist', methods=["POST"])
def check_domain():
    try:
        data=request.json
        domain=data.get("domain")
        if not domain:
            return jsonify({"error": "Missing 'domain' field in request"}), 400
        result = check_domain_virustotal(API_KEY, domain)
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

# --------- Run the App ---------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(debug=True, host='0.0.0.0', port=port)