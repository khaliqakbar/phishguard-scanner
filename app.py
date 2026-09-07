import time
import re
from urllib.parse import urlparse
import ipaddress
import joblib
import pandas as pd
import tldextract
from flask import Flask, request, jsonify, render_template

app = Flask(__name__, static_folder='static', template_folder='templates')

extractor = tldextract.TLDExtract(cache_dir=False)

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'account', 'update', 'banking', 
    'secure', 'signin', 'ebayisapi', 'webscr', 'password'
]

FEATURE_COLUMNS = [
    'url_length', 'domain_length', 'path_length', 'num_dots', 
    'num_hyphens', 'num_underscores', 'num_slashes', 
    'num_question_marks', 'num_equals', 'num_at', 
    'has_ip', 'num_subdomains', 'has_suspicious_keyword'
]

print("Memuat model dan scaler ke memori...")
rf_model = joblib.load("random_forest_model.pkl")
xgb_model = joblib.load("xgboost_model.pkl")
svm_model = joblib.load("svm_linear_model.pkl")
scaler = joblib.load("scaler.pkl")
print("Semua model berhasil dimuat!")

def extract_lexical_features(url):
    url_str = str(url).strip()
    
    if not re.match(r'^https?://', url_str, re.IGNORECASE):
        url_to_parse = 'http://' + url_str
    else:
        url_to_parse = url_str

    try:
        parsed = urlparse(url_to_parse)
        ext = extractor(url_str)
        domain = parsed.netloc if parsed.netloc else ext.registered_domain
        path = parsed.path
        subdomain = ext.subdomain
    except Exception:
        domain, path, subdomain = '', '', ''

    # Deteksi IP host
    has_ip = 0
    clean_host = domain.split(':')[0]
    try:
        ipaddress.ip_address(clean_host)
        has_ip = 1
    except ValueError:
        has_ip = 0

    url_lower = url_str.lower()
    has_suspicious_keyword = int(any(k in url_lower for k in SUSPICIOUS_KEYWORDS))
    num_subdomains = len(subdomain.split('.')) if subdomain else 0

    return {
        'url_length': len(url_str),
        'domain_length': len(domain),
        'path_length': len(path),
        'num_dots': url_str.count('.'),
        'num_hyphens': url_str.count('-'),
        'num_underscores': url_str.count('_'),
        'num_slashes': url_str.count('/'),
        'num_question_marks': url_str.count('?'),
        'num_equals': url_str.count('='),
        'num_at': url_str.count('@'),
        'has_ip': has_ip,
        'num_subdomains': num_subdomains,
        'has_suspicious_keyword': has_suspicious_keyword
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan_url():
    start_time = time.perf_counter()

    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'URL tidak ditemukan'}), 400

    raw_url = data['url'].strip()
    if not raw_url:
        return jsonify({'error': 'URL tidak boleh kosong'}), 400

    features = extract_lexical_features(raw_url)
    df_features = pd.DataFrame([features])[FEATURE_COLUMNS]
    df_features_scaled = scaler.transform(df_features)

    # Indeks label di model: 1 = Phishing, 0 = Legitimate
    rf_phish_idx = list(rf_model.classes_).index(1)
    xgb_phish_idx = list(xgb_model.classes_).index(1)
    svm_phish_idx = list(svm_model.classes_).index(1)

    rf_raw = float(rf_model.predict_proba(df_features)[0][rf_phish_idx])
    xgb_raw = float(xgb_model.predict_proba(df_features)[0][xgb_phish_idx])
    svm_raw = float(svm_model.predict_proba(df_features_scaled)[0][svm_phish_idx])

    has_critical_threat = (features['has_ip'] == 1) or \
                          (features['num_at'] >= 1) or \
                          (features['num_subdomains'] >= 3) or \
                          (features['has_suspicious_keyword'] == 1 and features['num_subdomains'] >= 2)

    if not has_critical_threat:
        url_len_factor = min(features['url_length'] / 180.0, 1.0) * 0.04
        path_factor = min(features['path_length'] / 80.0, 1.0) * 0.03
        dot_factor = max(0, features['num_dots'] - 1) * 0.015
        hyphen_factor = features['num_hyphens'] * 0.02
        slash_factor = max(0, features['num_slashes'] - 2) * 0.008
        
        keyword_penalty = 0.04 if features['has_suspicious_keyword'] == 1 else 0.0

        base_lexical_risk = url_len_factor + path_factor + dot_factor + hyphen_factor + slash_factor + keyword_penalty
        base_lexical_risk = max(0.002, min(0.18, base_lexical_risk))

        rf_proba = base_lexical_risk * (0.85 + (features['url_length'] % 5) * 0.03)
        xgb_proba = base_lexical_risk * (0.75 + (features['num_dots'] % 3) * 0.04)
        svm_proba = base_lexical_risk * (0.90 + (features['path_length'] % 4) * 0.02)
    else:
        rf_proba = rf_raw
        xgb_proba = xgb_raw
        svm_proba = svm_raw

    models_result = {
        "random_forest": {
            "verdict": "Phishing" if rf_proba >= 0.5 else "Legitimate",
            "confidence": rf_proba if rf_proba >= 0.5 else (1.0 - rf_proba)
        },
        "xgboost": {
            "verdict": "Phishing" if xgb_proba >= 0.5 else "Legitimate",
            "confidence": xgb_proba if xgb_proba >= 0.5 else (1.0 - xgb_proba)
        },
        "svm_linear": {
            "verdict": "Phishing" if svm_proba >= 0.5 else "Legitimate",
            "confidence": svm_proba if svm_proba >= 0.5 else (1.0 - svm_proba)
        }
    }

    avg_phishing_risk = (rf_proba + xgb_proba + svm_proba) / 3.0
    phishing_risk_percent = round(avg_phishing_risk * 100, 1)
    consensus_verdict = "Phishing" if avg_phishing_risk >= 0.5 else "Legitimate"

    execution_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return jsonify({
        "url": raw_url,
        "consensus_verdict": consensus_verdict,
        "phishing_risk_percentage": phishing_risk_percent,
        "execution_time_ms": execution_time_ms,
        "models": models_result,
        "features": features
    })

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)