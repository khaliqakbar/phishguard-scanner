import pandas as pd

print("1. Membaca dataset.csv...")
df = pd.read_csv("dataset.csv")

def normalize_url(url):
    url_str = str(url).strip()
    
    # Tambahkan skema standar jika belum ada
    if not url_str.startswith(("http://", "https://")):
        url_str = "https://" + url_str
        
    # Tambahkan trailing slash pada root domain jika tidak ada path
    scheme_offset = 8 if url_str.startswith("https://") else 7
    if "/" not in url_str[scheme_offset:]:
        url_str = url_str + "/"
        
    return url_str

print("2. Menyeragamkan format URL...")
df['url'] = df['url'].apply(normalize_url)

# Hapus duplikat pasca-normalisasi
initial_count = len(df)
df = df.drop_duplicates(subset=['url']).dropna(subset=['url', 'label'])
print(f"Dihapus {initial_count - len(df)} baris duplikat/kosong. Tersisa: {len(df)} baris.")

output_file = "dataset_cleaned.csv"
df.to_csv(output_file, index=False)
print(f"Selesai! File {output_file} berhasil dibuat.")