/**
 * PhishGuard.AI - Dashboard Controller & PDF Generator
 * Komunikasi Asynchronous dengan Flask Backend
 */

let lastScanData = null;
const auditHistory = [];

const FEATURE_GUIDE = {
  consensus_verdict: {
    title: 'Consensus Verdict',
    badge: 'Status Utama',
    desc: 'Ini adalah keputusan akhir sistem setelah tiga model machine learning (Random Forest, XGBoost, dan Linear SVM) “berunding”. Kartu ini menampilkan apakah URL dinilai aman atau phishing, plus perkiraan risikonya dalam persen. Status STANDBY berarti Anda belum memindai tautan apa pun.',
    risk: 'Phishing berbahaya justru karena tampilannya sering meyakinkan. Verdict konsensus dipakai agar keputusan tidak bergantung pada satu algoritma saja: jika mayoritas model melihat pola berbahaya pada struktur URL, sistem menaikkan peringatan agar pengguna tidak buru-buru mengklik atau mengisi data.'
  },
  url_length: {
    title: 'URL Length',
    badge: 'Vektor Leksikal',
    desc: 'Mengukur berapa banyak karakter di seluruh tautan. URL resmi biasanya relatif ringkas dan mudah dibaca. Tautan sangat panjang sering dibuat agar mata kita capek membaca, sehingga nama domain asli tersembunyi di tengah “sampah” teks.',
    risk: 'Penyerang menyembunyikan identitas domain asli di balik rantai karakter, parameter, dan folder palsu. Panjang URL yang tidak wajar menjadi sinyal bahwa tautan mungkin dirancang untuk mengelabui, bukan untuk memudahkan pengguna.'
  },
  domain_length: {
    title: 'Domain Length',
    badge: 'Vektor Leksikal',
    desc: 'Domain adalah “nama rumah” situs (contoh: bankku.co.id). Nama resmi biasanya pendek dan mudah diingat. Domain yang terlalu panjang sering meniru merek terkenal dengan menambahkan kata ekstra, misalnya login-bca-resmi-verifikasi.com.',
    risk: 'Tiruan nama merek (brand impersonation) hampir selalu menghasilkan domain lebih panjang dari aslinya. Sistem memantau panjang domain karena pola ini sering muncul pada situs palsu yang menyamar sebagai bank, marketplace, atau layanan pemerintah.'
  },
  path_length: {
    title: 'Path Length',
    badge: 'Vektor Leksikal',
    desc: 'Path adalah bagian URL setelah nama domain, seperti /akun/login/verifikasi. Situs sah memakai path seperlunya. Path yang sangat panjang biasanya berisi folder berlapis yang sengaja dibuat rumit agar tautan terlihat “resmi” atau “dalam sekali”.',
    risk: 'Struktur direktori berlapis dipakai untuk menyamarkan halaman palsu di dalam path yang tampak teknis. Korban cenderung percaya karena URL-nya “penuh folder”, padahal folder itu hanya dekorasi untuk menipu.'
  },
  num_subdomains: {
    title: 'Subdomains',
    badge: 'Vektor Leksikal',
    desc: 'Subdomain adalah label di kiri nama utama, misalnya shop.contoh.com. Situs besar memang punya beberapa subdomain. Masalahnya, penyerang bisa menulis nama bank di subdomain, misalnya bca.keamanan.situsjahat.com — yang terlihat seperti BCA, padahal rumah aslinya situsjahat.com.',
    risk: 'Ini disebut subdomain spoofing. Banyak orang hanya membaca kata merek di depan, bukan domain inti di belakang. Jumlah subdomain yang berlebih menjadi indikasi tautan sedang meminjam nama merek agar terasa familiar.'
  },
  has_ip: {
    title: 'IP Address',
    badge: 'Vektor Leksikal',
    desc: 'Situs resmi hampir selalu memakai nama domain (contoh: google.com), bukan deretan angka. Jika host-nya langsung berupa alamat IP seperti 192.168.1.1, peramban tidak menampilkan nama merek yang bisa Anda kenali.',
    risk: 'Host IP memotong kepercayaan yang biasanya diberikan sertifikat dan nama domain resmi. Penyerang memakai IP agar tidak perlu membeli domain yang mirip merek, dan agar jejak merek asli tidak muncul di bilah alamat.'
  },
  num_dots: {
    title: 'Dots (.)',
    badge: 'Vektor Leksikal',
    desc: 'Titik memisahkan bagian domain: www, nama situs, dan akhiran seperti .com. Beberapa titik wajar. Terlalu banyak titik biasanya berarti ada rantai subdomain tiruan bertingkat yang sengaja membingungkan.',
    risk: 'Titik berlebih sering dipakai merakit subdomain palsu bertingkat (contoh: login.bank.aman.situspalsu.net). Mata kita tertarik pada kata “bank”, sementara titik-titik itu menyembunyikan pemilik sebenarnya.'
  },
  num_hyphens: {
    title: 'Hyphens (-)',
    badge: 'Vektor Leksikal',
    desc: 'Tanda minus kadang dipakai di domain sah, tetapi jarang berlebihan. Penyerang suka merangkai kata merek dengan kata umpan: klik-bca, login-dana, atau verifikasi-akun-bri. Teknik ini disebut combosquatting.',
    risk: 'Combosquatting menempelkan kata yang terdengar resmi di samping nama merek. Jumlah tanda minus yang tinggi menandai URL yang “dirakit” agar mirip layanan tepercaya, bukan nama domain yang memang dimiliki merek tersebut.'
  },
  num_underscores: {
    title: 'Underscores (_)',
    badge: 'Vektor Leksikal',
    desc: 'Garis bawah hampir tidak dipakai pada nama domain standar. Jika muncul banyak di URL, itu biasanya bukan kebiasaan situs profesional, melainkan karakter yang ditambahkan agar tautan terlihat unik atau teknis.',
    risk: 'Karakter tidak lazim ini membantu membedakan tautan rekayasa dari domain bersih. Situs phishing sering mencomot pola acak, termasuk underscore, karena mereka tidak terikat standar merek resmi.'
  },
  num_slashes: {
    title: 'Slashes (/)',
    badge: 'Vektor Leksikal',
    desc: 'Garis miring memisahkan folder di path. Beberapa slash wajar (contoh: /produk/sepatu). Terlalu banyak slash membuat tautan tampak dalam dan rumit, sehingga orang kesulitan membaca di mana nama situsnya berakhir.',
    risk: 'Trik ini menyamarkan path folder agar korban bingung membaca tautan. Semakin banyak lapisan /, semakin mudah menyisipkan halaman palsu di “kedalaman” yang seolah-olah bagian dari situs resmi.'
  },
  num_at: {
    title: 'At Symbol (@)',
    badge: 'Vektor Leksikal',
    desc: 'Simbol @ di URL punya arti khusus: peramban menganggap teks sebelum @ sebagai nama pengguna, lalu benar-benar membuka alamat setelahnya. Contohnya, https://bca.co.id@situsjahat.com terlihat seperti BCA, tetapi yang dibuka adalah situsjahat.com.',
    risk: 'Bahayanya, teks di depan @ diabaikan oleh peramban. Penyerang menaruh nama merek di kiri agar mata kita tenang, sementara tujuan aslinya ada di kanan. Kehadiran @ di URL publik hampir selalu sinyal tipuan.'
  },
  num_question_marks: {
    title: 'Question (?)',
    badge: 'Vektor Leksikal',
    desc: 'Tanda tanya memulai query string: data tambahan setelah halaman, misalnya ?id=12. Situs biasa memakainya untuk pencarian atau filter. Jika terlalu banyak atau terasa acak, itu bisa berupa token pelacak, parameter umpan, atau tautan yang disalin dari skrip phishing.',
    risk: 'Parameter query sering membawa pelacak atau token bypass agar halaman palsu “terlihat personal”. Pola ? yang mencurigakan membantu sistem menangkap tautan yang membawa korban ke alur verifikasi palsu.'
  },
  num_equals: {
    title: 'Equals (=)',
    badge: 'Vektor Leksikal',
    desc: 'Tanda sama dengan mengisi nilai pada query, seperti user=andi atau token=abc. Formulir login palsu sering menempelkan banyak pasangan nama=nilai di URL untuk mengirim atau menyimpan data yang diketik korban.',
    risk: 'Variabel query dengan banyak = dipakai mengirim kredensial dari form palsu atau meniru sesi login. Sistem menghitung karakter ini karena halaman phishing sering “mengemas” data akun langsung di tautan.'
  },
  has_suspicious_keyword: {
    title: 'Suspicious Keyword',
    badge: 'Vektor Leksikal',
    desc: 'Sistem mencari kata pancingan yang memicu rasa panik atau buru-buru: login, verify, update, secure, diskon, hadiah, dan sejenisnya. Kata-kata itu tidak otomatis berarti jahat, tetapi sering dipakai dalam kampanye yang menekan emosi.',
    risk: 'Phishing bekerja lewat psikologi: rasa takut akun dibekukan atau tergiur promo. Kata kunci mencurigakan menandai tautan yang mendorong korban segera mengisi sandi, OTP, atau data kartu tanpa sempat memeriksa domain.'
  },
  engine_mode: {
    title: 'Engine Mode',
    badge: 'Arsitektur Deteksi',
    desc: 'Mode Air-Gapped (Static) berarti analisis hanya membaca teks URL secara lokal, mengikuti aturan alamat web RFC 3986. Tidak ada kunjungan ke situs target, tidak ada crawling, dan tidak ada ketergantungan ke internet saat memutuskan.',
    risk: 'Mengunjungi tautan phishing justru bisa memicu unduhan malware atau mencatat IP Anda. Mesin leksikal statis dipakai agar deteksi tetap aman: cukup memeriksa “bentuk tulisan” URL, tanpa membuka pintu ke server penyerang.'
  }
};

document.addEventListener('DOMContentLoaded', () => {
  const scanBtn = document.getElementById('scanBtn');
  const urlInput = document.getElementById('urlInput');
  const downloadPdfBtn = document.getElementById('downloadPdfBtn');

  if (scanBtn) {
    scanBtn.addEventListener('click', executeScan);
  }

  if (urlInput) {
    urlInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        executeScan();
      }
    });
  }

  if (downloadPdfBtn) {
    downloadPdfBtn.addEventListener('click', downloadPdfReport);
  }

  initSidebarNav();
  initFeatureModals();
});

function initFeatureModals() {
  const modal = document.getElementById('eduModal');
  if (!modal) return;

  const titleEl = document.getElementById('modalTitle');
  const badgeEl = document.getElementById('modalBadge');
  const descEl = document.getElementById('modalDesc');
  const riskEl = document.getElementById('modalRiskWhy');

  const openModal = (featureKey) => {
    const info = FEATURE_GUIDE[featureKey];
    if (!info) return;

    titleEl.textContent = info.title;
    badgeEl.textContent = info.badge;
    descEl.textContent = info.desc;
    riskEl.textContent = info.risk;

    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
  };

  const closeModal = () => {
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
  };

  document.querySelectorAll('.btn-info-modal').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      openModal(btn.dataset.feature);
    });
  });

  document.getElementById('modalCloseX')?.addEventListener('click', closeModal);
  document.getElementById('modalUnderstand')?.addEventListener('click', closeModal);
  modal.querySelector('[data-modal-dismiss]')?.addEventListener('click', closeModal);

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal.classList.contains('is-open')) {
      closeModal();
    }
  });
}

function initSidebarNav() {
  const buttons = document.querySelectorAll('.sidebar-btn[data-nav]');
  const panels = {
    dashboard: document.getElementById('panel-dashboard'),
    features: document.getElementById('panel-features'),
    stream: document.getElementById('panel-stream')
  };

  buttons.forEach((btn) => {
    btn.addEventListener('click', () => {
      buttons.forEach((item) => item.classList.remove('active'));
      btn.classList.add('active');

      const target = panels[btn.dataset.nav];
      if (!target) return;

      target.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      target.classList.remove('panel-focus');
      void target.offsetWidth;
      target.classList.add('panel-focus');
    });
  });
}

function setQuickUrl(url) {
  const input = document.getElementById('urlInput');
  if (input) {
    input.value = url;
    executeScan();
  }
}

async function executeScan() {
  const urlInput = document.getElementById('urlInput');
  const scanBtn = document.getElementById('scanBtn');
  const scanBtnText = document.getElementById('scanBtnText');
  const scanBtnIcon = document.getElementById('scanBtnIcon');

  const rawUrl = urlInput.value.trim();
  if (!rawUrl) {
    alert('Silakan masukkan URL target terlebih dahulu.');
    urlInput.focus();
    return;
  }

  // Visual indikator loading
  scanBtn.disabled = true;
  scanBtnText.innerText = 'Scanning...';
  scanBtnIcon.className = 'fa-solid fa-spinner fa-spin';

  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: rawUrl })
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.error || `Server HTTP Error: ${response.status}`);
    }

    const data = await response.json();
    lastScanData = data;

    renderScanResults(data);
    addAuditHistory(data);

  } catch (err) {
    alert(`Gagal Melakukan Analisis: ${err.message}`);
  } finally {
    scanBtn.disabled = false;
    scanBtnText.innerText = 'Scan URL';
    scanBtnIcon.className = 'fa-solid fa-arrow-right';
  }
}

function renderScanResults(data) {
  const verdictCard = document.getElementById('verdictCard');
  const riskBadge = document.getElementById('riskBadge');
  const verdictText = document.getElementById('verdictText');
  const riskScore = document.getElementById('riskScore');
  const latencyHero = document.getElementById('latencyHero');

  const isPhishing = data.consensus_verdict === 'Phishing';

  // 1. Kartu Verdict
  if (isPhishing) {
    verdictCard.className = 'card card-verdict danger';
    riskBadge.innerText = 'THREAT DETECTED';
  } else {
    verdictCard.className = 'card card-verdict safe';
    riskBadge.innerText = 'LEGITIMATE / SAFE';
  }

  verdictText.innerText = data.consensus_verdict;
  riskScore.innerText = `${data.phishing_risk_percentage}%`;
  latencyHero.innerText = `${data.execution_time_ms}ms`;

  // 2. Tiga Sub-Model
  if (data.models) {
    updateModelBar('rf', data.models.random_forest);
    updateModelBar('xgb', data.models.xgboost);
    updateModelBar('svm', data.models.svm_linear);
  }

  // 3. 13 Vektor Fitur Leksikal Penuh
  if (data.features) {
    const f = data.features;
    setFieldText('feat_url_length', f.url_length);
    setFieldText('feat_domain_length', f.domain_length);
    setFieldText('feat_path_length', f.path_length);
    setFieldText('feat_num_subdomains', f.num_subdomains);
    setFieldText('feat_has_ip', f.has_ip === 1 ? 'YES' : 'NO');
    setFieldText('feat_num_dots', f.num_dots);
    setFieldText('feat_num_hyphens', f.num_hyphens);
    setFieldText('feat_num_underscores', f.num_underscores);
    setFieldText('feat_num_slashes', f.num_slashes);
    setFieldText('feat_num_at', f.num_at);
    setFieldText('feat_num_question_marks', f.num_question_marks);
    setFieldText('feat_num_equals', f.num_equals);
    setFieldText('feat_has_suspicious_keyword', f.has_suspicious_keyword === 1 ? 'YES' : 'NO');
  }
}

function updateModelBar(prefix, modelData) {
  if (!modelData) return;
  const pct = (modelData.confidence * 100).toFixed(1);
  const textEl = document.getElementById(`${prefix}Conf`);
  const barEl = document.getElementById(`${prefix}Bar`);

  if (textEl) textEl.innerText = `${pct}% (${modelData.verdict})`;
  if (barEl) barEl.style.width = `${pct}%`;
}

function setFieldText(elemId, value) {
  const el = document.getElementById(elemId);
  if (el) el.innerText = (value !== undefined && value !== null) ? value : '-';
}

function addAuditHistory(data) {
  const tbody = document.getElementById('historyTableBody');
  if (!tbody) return;

  auditHistory.unshift(data);
  if (auditHistory.length > 8) auditHistory.pop();

  tbody.innerHTML = '';
  auditHistory.forEach(item => {
    const tr = document.createElement('tr');
    const isPhish = item.consensus_verdict === 'Phishing';
    const shortUrl = item.url.length > 28 ? item.url.substring(0, 26) + '...' : item.url;

    tr.innerHTML = `
      <td class="url-cell" title="${item.url}" style="font-weight: 600;">${shortUrl}</td>
      <td>
        <span class="badge-res ${isPhish ? 'phish' : 'safe'}">
          ${item.consensus_verdict}
        </span>
      </td>
      <td class="text-right" style="font-weight: 700; color: #64748b;">${item.execution_time_ms}ms</td>
    `;
    tbody.appendChild(tr);
  });
}

function downloadPdfReport() {
  if (!lastScanData) {
    alert('Belum ada data scan. Silakan jalankan scanning URL terlebih dahulu.');
    return;
  }

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();
  const d = lastScanData;

  // Header Dokumen
  doc.setFillColor(18, 22, 32);
  doc.rect(0, 0, 210, 26, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text('PHISHGUARD.AI // FORENSIC AUDIT REPORT', 14, 16);

  // Metadata Target
  doc.setTextColor(30, 41, 59);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.text(`Target URL       : ${d.url}`, 14, 36);
  doc.text(`Consensus Verdict: ${d.consensus_verdict.toUpperCase()}`, 14, 43);
  doc.text(`Risk Probability : ${d.phishing_risk_percentage}%`, 14, 50);
  doc.text(`Execution Time   : ${d.execution_time_ms} ms (Air-Gapped Lexical Engine)`, 14, 57);

  // Tabel Evaluasi Model
  const modelRows = [
    ['Random Forest', d.models.random_forest.verdict, `${(d.models.random_forest.confidence * 100).toFixed(1)}%`],
    ['XGBoost Classifier', d.models.xgboost.verdict, `${(d.models.xgboost.confidence * 100).toFixed(1)}%`],
    ['Linear SVM', d.models.svm_linear.verdict, `${(d.models.svm_linear.confidence * 100).toFixed(1)}%`]
  ];

  doc.autoTable({
    startY: 65,
    head: [['Machine Learning Sub-Model', 'Verdict', 'Confidence']],
    body: modelRows,
    theme: 'striped',
    headStyles: { fillColor: [18, 22, 32] },
    styles: { fontSize: 9 }
  });

  // Tabel 13 Fitur Leksikal
  const feat = d.features || {};
  const featRows = [
    ['URL Length', feat.url_length, 'Dots Count (.)', feat.num_dots],
    ['Domain Length', feat.domain_length, 'Hyphens Count (-)', feat.num_hyphens],
    ['Path Length', feat.path_length, 'Underscores (_)', feat.num_underscores],
    ['Subdomain Count', feat.num_subdomains, 'Slashes (/)', feat.num_slashes],
    ['IP Host Address', feat.has_ip === 1 ? 'YES' : 'NO', 'At Symbol (@)', feat.num_at],
    ['Suspicious Word', feat.has_suspicious_keyword === 1 ? 'YES' : 'NO', 'Question Mark (?)', feat.num_question_marks]
  ];

  doc.autoTable({
    startY: doc.lastAutoTable.finalY + 10,
    head: [['Feature Indicator (A)', 'Value', 'Feature Indicator (B)', 'Value']],
    body: featRows,
    theme: 'grid',
    headStyles: { fillColor: [71, 85, 105] },
    styles: { fontSize: 8.5 }
  });

  // Footer Dokumen
  const finalY = doc.lastAutoTable.finalY + 15;
  doc.setFontSize(8.5);
  doc.setTextColor(148, 163, 184);
  doc.text('Skripsi Project © 2026 - Air-Gapped Zero-Day Lexical Detection Methodology', 14, finalY);

  doc.save(`PhishGuard_Report_${Date.now()}.pdf`);
}