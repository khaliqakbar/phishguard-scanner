import pandas as pd

# 1. Baca PhishTank (verified_online.csv)
print("[-] Membaca PhishTank...")
df_phish = pd.read_csv('verified_online.csv', low_memory=False)

# Ambil kolom 'url', bersihkan spasi, dan beri label 1
df_phish_clean = pd.DataFrame({
    'url': df_phish['url'].dropna().astype(str).str.strip(),
    'label': 1
})
print(f"    Jumlah Phishing: {len(df_phish_clean):,}")

# 2. Baca Tranco (top-1m(tranco).csv) - Ambil 100.000 data teratas
print("[-] Membaca Tranco (Top 100.000)...")
df_tranco = pd.read_csv('top-1m(tranco).csv', header=None, nrows=100000)

# Kolom index 1 adalah domain, beri label 0
df_tranco_clean = pd.DataFrame({
    'url': df_tranco[1].dropna().astype(str).str.strip(),
    'label': 0
})
print(f"    Jumlah Legitimate: {len(df_tranco_clean):,}")

# 3. Gabungkan kedua data
print("[-] Menggabungkan data...")
dataset = pd.concat([df_phish_clean, df_tranco_clean], ignore_index=True)

# 4. Hapus duplikasi jika ada
dataset.drop_duplicates(subset=['url'], inplace=True)
dataset = dataset[dataset['url'] != '']

# 5. Acak posisi data (Shuffle)
dataset = dataset.sample(frac=1.0, random_state=42).reset_index(drop=True)

# 6. Ekspor ke dataset.csv
output_file = 'dataset.csv'
dataset.to_csv(output_file, index=False)

print(f"\n[+] Sukses membuat '{output_file}'!")
print(f"    Total baris     : {len(dataset):,}")
print(f"    Phishing (1)    : {(dataset['label'] == 1).sum():,}")
print(f"    Legitimate (0)  : {(dataset['label'] == 0).sum():,}")