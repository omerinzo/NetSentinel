<div align="center">

```
███╗   ██╗███████╗████████╗███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
██║ ╚████║███████╗   ██║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
```

**Çok Modüllü Ağ Güvenlik Keşif Aracı**

[![Python](https://img.shields.io/badge/Python-3.10+-3776ab?style=flat&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![Modules](https://img.shields.io/badge/Modules-4-blue?style=flat)](modules/)
[![Education](https://img.shields.io/badge/Purpose-Educational-orange?style=flat)]()

</div>

---

## Nedir?

**NetSentinel**, Python ile yazılmış, ek kütüphane gerektirmeyen (sadece standart lib) bir ağ güvenlik keşif aracıdır. Siber güvenlik profesyonellerinin beş farklı araçla yaptığı analizi tek komutta sunar.

> **Yasal Uyarı:** Bu araç yalnızca izin verilen sistemlerde ve eğitim amaçlı kullanılmalıdır. Test için [scanme.nmap.org](http://scanme.nmap.org) kullanabilirsiniz.

---

## Modüller

| Modül | Dosya | Ne Yapar? |
|---|---|---|
| 🔍 **Port Tarayıcı** | `modules/port_scanner.py` | TCP port tarama + Banner Grabbing (SSH, FTP, HTTP versiyon tespiti) |
| 🔒 **SSL Analizörü** | `modules/ssl_check.py` | Sertifika geçerlilik, TLS versiyonu, cipher suite, self-signed kontrolü |
| 🌐 **HTTP Denetçisi** | `modules/http_headers.py` | HSTS, CSP, X-Frame-Options, Referrer-Policy vb. güvenlik başlıkları |
| 📡 **DNS Keşfi** | `modules/dns_recon.py` | A, AAAA, MX, NS, TXT (SPF, DMARC) kayıt sorgulaması |
| 📊 **Rapor Üretici** | `modules/reporter.py` | HTML (dark theme) + JSON rapor çıktısı |

---

## Kurulum

```bash
git clone https://github.com/omerinzo/NetSentinel.git
cd NetSentinel
python netsentinel.py --help
```

Ek kütüphane **gerekmez** — tüm modüller Python standart kütüphanesi kullanır.

---

## Kullanım

```bash
# Temel tarama (tüm modüller)
python netsentinel.py tara --hedef scanme.nmap.org

# HTML + JSON rapor oluştur
python netsentinel.py tara --hedef example.com --html --json

# Belirli portları tara
python netsentinel.py tara --hedef 192.168.1.1 --portlar 22,80,443,8080

# Web portlarına odaklan
python netsentinel.py tara --hedef example.com --port-grubu web

# Tam port tarama (1-1024), sadece DNS ve HTTP
python netsentinel.py tara --hedef target.com --port-grubu tam --skip-ssl

# Hızlı tarama (sadece port + banner)
python netsentinel.py tara --hedef 10.0.0.1 --skip-ssl --skip-http --skip-dns
```

### Port Grupları

| Grup | Portlar |
|---|---|
| `hizli` | 21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080 |
| `web` | 80, 443, 8080, 8443, 8888, 3000, 4000, 5000, 9000 |
| `veritabani` | 1433, 1521, 3306, 5432, 6379, 9200, 27017 |
| `tam` | 1 – 1024 (tüm standart portlar) |

---

## Örnek Çıktı

```
  Hedef   : scanme.nmap.org
  IP      : 45.33.32.156

──────────────────────────────────────────────
  🔍  PORT TARAMA + BANNER GRABBING
──────────────────────────────────────────────
  PORT     SERVİS           BANNER
  22       SSH              SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
  80       HTTP             HTTP/1.1 200 OK

──────────────────────────────────────────────
  🔒  SSL/TLS SERTİFİKA ANALİZİ
──────────────────────────────────────────────
  Alan Adı       : example.com
  Veren Kurum    : Let's Encrypt
  TLS Versiyonu  : TLSv1.3
  Kalan Süre     : 87 gün kaldı ✓

──────────────────────────────────────────────
  🌐  HTTP GÜVENLİK BAŞLIKLARI
──────────────────────────────────────────────
  Güvenlik Skoru: 55/100

  ✓ Strict-Transport-Security     Var
  ✗ Content-Security-Policy       Eksik
  ✓ X-Frame-Options               Var

──────────────────────────────────────────────
  📡  DNS KEŞİF MOTORU
──────────────────────────────────────────────
  A Kayıtları (IPv4):
    45.33.32.156
  SPF Kaydı  : ✓ Var
  DMARC      : ✓ Var
```

---

## Proje Yapısı

```
NetSentinel/
├── netsentinel.py           ← Ana CLI (giriş noktası)
├── modules/
│   ├── __init__.py
│   ├── port_scanner.py      ← Port tarama + banner grabbing
│   ├── ssl_check.py         ← SSL/TLS sertifika analizi
│   ├── http_headers.py      ← HTTP güvenlik başlıkları
│   ├── dns_recon.py         ← DNS keşif motoru
│   └── reporter.py          ← HTML + JSON rapor üretici
├── raporlar/                ← Otomatik oluşturulan raporlar
├── requirements.txt
└── README.md
```

---

## Öğrenilen Kavramlar

| Kavram | Nerede? |
|---|---|
| TCP 3-Way Handshake | `port_scanner.py` |
| Banner Grabbing | `port_scanner.py` |
| SSL/TLS sertifika yapısı | `ssl_check.py` |
| HTTP güvenlik başlıkları (HSTS, CSP) | `http_headers.py` |
| DNS kayıt türleri (A, MX, NS, TXT) | `dns_recon.py` |
| SPF / DMARC e-posta güvenliği | `dns_recon.py` |
| Çok iş parçacıklı programlama | `port_scanner.py` |
| HTML rapor üretimi | `reporter.py` |

---

<div align="center">

**NetSentinel** — Eğitim amaçlı geliştirilmiştir. Yalnızca yetkili sistemlerde kullanın.

</div>
