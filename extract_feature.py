import re
from urllib.parse import urlparse
import ipaddress
import pandas as pd
import tldextract

extractor = tldextract.TLDExtract(cache_dir=False)

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'account', 'update', 'banking', 
    'secure', 'signin', 'ebayisapi', 'webscr', 'password'
]

def extract_lexical_features(url):
    url_str = str(url)
    
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

    # Deteksi IP Address host
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

print("Membaca dataset_cleaned.csv...")
df = pd.read_csv("dataset_cleaned.csv")

print(f"Mengekstrak fitur dari {len(df)} data URL...")
feature_records = [extract_lexical_features(u) for u in df['url']]

features_df = pd.DataFrame(feature_records)
features_df['label'] = df['label'].values

output_file = "dataset_features.csv"
features_df.to_csv(output_file, index=False)
print(f"Selesai! File {output_file} berhasil diperbarui.")