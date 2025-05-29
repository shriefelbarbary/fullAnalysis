from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import re
import requests
import hashlib
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
import whois
import tempfile

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Constants for colored output (not needed in API, but kept for reference)
RED, WHITE, YELLOW, CIANO, GREEN, END = '\033[91m', '\033[46m', '\033[93m', '\033[100m', '\033[1;32m', '\033[0m'

# VirusTotal API Key (consider using environment variables for security)
VIRUSTOTAL_API_KEY = "7019e4123a3e38c9ed8f8afd087ace44d8a02cb686b5f0227d60b59d8cc8a3eb"

def check_virustotal_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        else:
            return {"error": f"Failed to retrieve data, status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def check_virustotal_url(url_to_check):
    url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        data = {"url": url_to_check}
        response = requests.post(url, headers=headers, data=data)
        if response.status_code == 200:
            json_response = response.json()
            url_id = json_response["data"]["id"]
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
            analysis_response = requests.get(analysis_url, headers=headers)
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
                return stats
            else:
                return {"error": f"Failed to retrieve analysis, status code: {analysis_response.status_code}"}
        else:
            return {"error": f"Failed to submit URL, status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def check_virustotal_file_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        elif response.status_code == 404:
            return {"error": "File not found in VirusTotal database."}
        else:
            return {"error": f"Failed to retrieve data, status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def get_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        return {
            "creation_date": str(domain_info.creation_date),
            "expiration_date": str(domain_info.expiration_date),
            "organization": domain_info.org,
        }
    except Exception as e:
        return {"error": str(e)}

def read_email_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        return msg
    except Exception as e:
        return None

def extract_basic_email_details(msg):
    sender = msg['From']
    recipient = msg['To']
    reply_to = msg['Reply-To']
    return_path = msg['Return-Path']
    date = msg['Date']
    subject = msg['Subject']
    sender_email, sender_name, sender_domain, sender_ip = None, None, None, "Not found"

    if sender:
        match = re.match(r'(.*)<(.*)>', sender)
        if match:
            sender_name = match.group(1).strip()
            sender_email = match.group(2).strip()
        else:
            sender_email = sender.strip()

    if sender_email:
        domain_match = re.search(r'@([a-zA-Z0-9.-]+)$', sender_email)
        sender_domain = domain_match.group(1) if domain_match else None

    spf, dmarc, dkim = "Not found in headers", "Not found", "Not found"
    for header in msg.keys():
        if header.lower() == "received-spf":
            spf = msg[header]
        elif header.lower().startswith("authentication-results"):
            auth_results = msg[header]
            if "dmarc=" in auth_results:
                dmarc_match = re.search(r"dmarc=(\w+)", auth_results)
                dmarc = dmarc_match.group(1) if dmarc_match else "Not found"
            if "dkim=" in auth_results:
                dkim_match = re.search(r"dkim=(\w+)", auth_results)
                dkim = dkim_match.group(1) if dkim_match else "Not found"

    return {
        "date": date,
        "sender_name": sender_name,
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "sender_ip": sender_ip,
        "reply_to": reply_to,
        "return_path": return_path,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "recipient": recipient,
        "subject": subject,
    }

def extract_urls_from_email(msg):
    urls = []
    try:
        if msg.is_multipart():
            parts = msg.walk()
            body = ""
            for part in parts:
                if part.get_content_type() == 'text/plain':
                    body += part.get_content()
        else:
            body = msg.get_content()

        url_regex = re.compile(r'((?:http|ftp)s?://[^\s/$.?#].[^\s]*)', re.IGNORECASE)
        urls = url_regex.findall(body)
        return urls
    except Exception as e:
        return []

def extract_attachments_from_email(msg, output_dir=None):
    attachments = []
    try:
        if output_dir is None:
            output_dir = tempfile.mkdtemp()
        os.makedirs(output_dir, exist_ok=True)
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            filename = part.get_filename()
            if filename:
                filepath = os.path.join(output_dir, filename)
                with open(filepath, 'wb') as fp:
                    content = part.get_payload(decode=True)
                    fp.write(content)
                attachments.append({
                    "filename": filename,
                    "filepath": filepath,
                    "sha256": hashlib.sha256(content).hexdigest()
                })
        return attachments
    except Exception as e:
        return []

@app.route('/analyze_email', methods=['POST'])
def analyize_email():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # Save the uploaded file temporarily
    temp_dir = tempfile.mkdtemp()
    file_path = os.path.join(temp_dir, file.filename)
    file.save(file_path)

    try:
        msg = read_email_file(file_path)
        if not msg:
            return jsonify({"error": "Failed to read the email file"}), 400

        # Extract basic details
        email_details = extract_basic_email_details(msg)

        # Analyze sender domain
        sender_domain = email_details.get('sender_domain')
        virustotal_domain_results = check_virustotal_domain(sender_domain) if sender_domain else None
        whois_info = get_whois_info(sender_domain) if sender_domain else None

        # Check for suspicious subject
        suspicious_words = ["urgent", "invoice", "payment", "sensitive", "action required"]
        suspicious_subject = False
        subject = email_details.get('subject', '').lower()
        for word in suspicious_words:
            if word.lower() in subject:
                suspicious_subject = True
                break

        # Extract URLs
        urls = extract_urls_from_email(msg)
        url_analyses = []
        for url in urls:
            url_analyses.append({
                "url": url,
                "virustotal": check_virustotal_url(url)
            })

        # Extract attachments
        attachments = extract_attachments_from_email(msg)
        attachment_analyses = []
        for attachment in attachments:
            attachment_analyses.append({
                "filename": attachment["filename"],
                "sha256": attachment["sha256"],
                "virustotal": check_virustotal_file_hash(attachment["sha256"])
            })

        # Clean up temporary files
        try:
            for attachment in attachments:
                if os.path.exists(attachment["filepath"]):
                    os.remove(attachment["filepath"])
            if os.path.exists(file_path):
                os.remove(file_path)
            os.rmdir(temp_dir)
        except:
            pass

        return jsonify({
            "email_details": email_details,
            "domain_analysis": {
                "virustotal": virustotal_domain_results,
                "whois": whois_info
            },
            "subject_analysis": {
                "is_suspicious": suspicious_subject,
                "suspicious_words_found": [word for word in suspicious_words if word in subject]
            },
            "url_analysis": url_analyses,
            "attachment_analysis": attachment_analyses
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(debug=True, host='0.0.0.0', port=port)
