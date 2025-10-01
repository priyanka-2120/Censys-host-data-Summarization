from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import json
import os
import urllib.request
import urllib.parse
from dotenv import load_dotenv

# Resolve directories relative to this file so templates/static are always found
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load environment variables from .env next to this file
load_dotenv(os.path.join(BASE_DIR, '.env'))

# Configure Flask with absolute template/static folders
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, 'templates'),
    static_folder=os.path.join(BASE_DIR, 'static'),
)
CORS(app)

# Set Perplexity API key from environment variable
PERPLEXITY_API_KEY = os.getenv('PERPLEXITY_API_KEY')

def analyze_host_data(host_data):
    """Analyze host data using Perplexity API"""
    
    prompt = f"""
    You are a security analyst summarizing Censys host data. Generate a concise summary for technical and non-technical audiences that includes:

    STRUCTURE:
    1. Executive Summary (2-3 sentences in plain language)
    2. Quick Metrics (bulleted counts)
    3. Overall Risk Assessment (concise, no repetition)
    4. Key Vulnerabilities (markdown table)
    5. Services and Security Issues (markdown table, one row per host)
    6. Notable Observations (3-5 concise bullets)
    7. Recommended Next Actions (3-5 bullets)

    EXECUTIVE SUMMARY REQUIREMENTS:
    - Start with 2-3 sentence high-level overview in plain language
    - Example: "Three servers were analyzed, revealing serious risks like hacker tools and software flaws. One server in China is highly dangerous due to malware, and all need urgent fixes."
    - Highlight most critical findings (malware, vulnerabilities) without technical jargon

    ACCESSIBILITY FOR NON-TECHNICAL USERS:
    - Use simple language for key terms or add brief explanations in parentheses
    - Examples: "Cobalt Strike (a hacking tool for remote control)", "username enumeration (guessing valid usernames)", "self-signed cert (less secure encryption)"
    - Keep technical details (CVEs, ports) in tables for experts but summarize simply in text

    LENGTH AND BREVITY:
    - Total length ~250-300 words (excluding tables), including executive summary
    - Condense verbose sentences: "FTP with self-signed TLS; vulnerable OpenSSH 8.9p1; multiple HTTP services (some restricted); MySQL access restricted"
    - Merge related points: "Two hosts in Chinese Huawei Cloud data centers (ASN 55990) and one in the US (ASN 263744) may have geopolitical or threat attribution implications"
    - Eliminate redundancy - detail CVEs only in table, reference briefly elsewhere

    OUTPUT FORMAT (Markdown):
    - Executive Summary
    - Quick Metrics (Total Hosts, Critical Risk, High Risk, Services, Unique Vulnerabilities, Countries)
    - Overall Risk Assessment
    - Key Vulnerabilities (CVE ID | Severity | CVSS | Affected Hosts | Service/Version | Brief Note)
    - Services and Security Issues (Host IP | Services & Ports | Key Issues/Notes)
    - Notable Observations
    - Recommended Next Actions

    TONE: Professional yet approachable for both technical and non-technical audiences.

    Host Data:
    {json.dumps(host_data, indent=2)}
    """
    
    try:
        headers = {
            "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": "sonar",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity analyst specializing in host data analysis."},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 1000,
            "temperature": 0.3
        }
        
        # Convert data to JSON string
        json_data = json.dumps(data).encode('utf-8')
        
        # Create request
        req = urllib.request.Request(
            "https://api.perplexity.ai/chat/completions",
            data=json_data,
            headers=headers,
            method='POST'
        )
        
        # Make request
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode('utf-8'))
            return result["choices"][0]["message"]["content"].strip()
            
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8')
        return f"Error generating summary: {e.code} - {error_body}"
    except Exception as e:
        return f"Error generating summary: {str(e)}"

def extract_key_metrics(hosts):
    """Extract key metrics from host data for quick overview"""
    metrics = {
        "total_hosts": len(hosts),
        "critical_risk": 0,
        "high_risk": 0,
        "unique_vulnerabilities": set(),
        "services_count": 0,
        "countries": set()
    }
    
    for host in hosts:
        risk_level = host.get("threat_intelligence", {}).get("risk_level", "").lower()
        if risk_level == "critical":
            metrics["critical_risk"] += 1
        elif risk_level == "high":
            metrics["high_risk"] += 1
        
        for service in host.get("services", []):
            metrics["services_count"] += 1
            for vuln in service.get("vulnerabilities", []):
                metrics["unique_vulnerabilities"].add(vuln.get("cve_id", "Unknown"))
        
        metrics["countries"].add(host.get("location", {}).get("country", "Unknown"))
    
    metrics["unique_vulnerabilities"] = list(metrics["unique_vulnerabilities"])
    metrics["countries"] = list(metrics["countries"])
    
    return metrics

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({"status": "ok"})

@app.route('/summarize', methods=['POST'])
def summarize():
    try:
        if request.content_type == 'application/json':
            data = request.get_json()
        else:
            data_str = request.form.get('data', '')
            if not data_str:
                return jsonify({"error": "No data provided"}), 400
            data = json.loads(data_str)
        
        if "hosts" not in data:
            return jsonify({"error": "Invalid data format. Expected 'hosts' array."}), 400
        
        metrics = extract_key_metrics(data["hosts"])
        ai_summary = analyze_host_data(data)
        
        response = {
            "metrics": metrics,
            "summary": ai_summary,
            "hosts_count": len(data["hosts"])
        }
        
        return jsonify(response)
    
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON format"}), 400
    except Exception as e:
        return jsonify({"error": f"Processing error: {str(e)}"}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', '5000'))
    app.run(debug=True, host='127.0.0.1', port=port)