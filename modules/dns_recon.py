"""
=============================================================
  NetSentinel — DNS Keşif Motoru
  ─────────────────────────────────────────────────────────
  Görev:
    Hedef domain hakkında DNS kayıtlarını sorgular.
    DNS keşfi, bir sistemin altyapısını anlamak için
    kullanılan temel siber güvenlik tekniğidir.

  Sorgulanan Kayıt Türleri:
    A     → IPv4 adresi              (domain → IP)
    AAAA  → IPv6 adresi
    MX    → Mail sunucuları          (e-posta altyapısı)
    NS    → Name server'lar          (DNS sunucuları)
    TXT   → Metin kayıtları          (SPF, DKIM, doğrulama)
    CNAME → Takma ad                 (CDN, alias tespiti)

  socket modülü ile temel DNS sorguları yapılabilir.
  Daha gelişmiş sorgular için dnspython gerekir.
=============================================================
"""

import socket
import subprocess
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DNSSonuc:
    """DNS keşif sonuçlarını tutar."""
    domain      : str
    hata        : str = ""

    # Kayıt listesi: { kayıt_türü: [değer1, değer2, ...] }
    a_kayitlar  : list = field(default_factory=list)   # IPv4
    aaaa_kayitlar: list = field(default_factory=list)  # IPv6
    mx_kayitlar : list = field(default_factory=list)   # Mail
    ns_kayitlar : list = field(default_factory=list)   # Name Server
    txt_kayitlar: list = field(default_factory=list)   # TXT (SPF, DKIM)
    cname       : str  = ""                            # Canonical Name

    # Güvenlik bulguları
    spf_var     : bool = False   # SPF kaydı var mı?
    dmarc_var   : bool = False   # DMARC kaydı var mı?
    bulgular    : list = field(default_factory=list)


def _nslookup_calistir(sorgu: str, tip: str = "A") -> list:
    """
    Sistemin nslookup veya dig komutunu çalıştırarak DNS sorgusu yapar.

    Args:
        sorgu : Sorgulanacak domain.
        tip   : Kayıt türü (A, MX, NS, TXT, AAAA).

    Returns:
        Ham çıktı satırlarının listesi.
    """
    try:
        # nslookup ile sorgula (Windows ve Linux'ta mevcut)
        sonuc = subprocess.run(
            ["nslookup", f"-type={tip}", sorgu],
            capture_output=True,
            text=True,
            timeout=8
        )
        return sonuc.stdout.splitlines()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def _socket_a_kaydi(domain: str) -> list:
    """
    socket.getaddrinfo() ile A ve AAAA kayıtlarını sorgular.
    Bu en temel ve her sistemde çalışan yöntemdir.

    Returns:
        [(ip_adresi, ip_versiyonu), ...] listesi
    """
    sonuclar = []
    try:
        # Tüm adres aileleri için çözümleme yap
        adresler = socket.getaddrinfo(domain, None)
        gordu = set()
        for aile, _, _, _, adres in adresler:
            ip = adres[0]
            if ip not in gordu:
                gordu.add(ip)
                if aile == socket.AF_INET:
                    sonuclar.append(("A", ip))
                elif aile == socket.AF_INET6:
                    sonuclar.append(("AAAA", ip))
    except socket.gaierror:
        pass
    return sonuclar


def _mx_sorgula(domain: str) -> list:
    """MX (mail exchange) kayıtlarını nslookup ile sorgular."""
    satirlar = _nslookup_calistir(domain, "MX")
    mx_listesi = []

    for satir in satirlar:
        # nslookup MX çıktısı: "mail exchanger = 10 mail.example.com."
        if "mail exchanger" in satir.lower():
            parcalar = satir.split("=")
            if len(parcalar) > 1:
                deger = parcalar[1].strip()
                # Öncelik ve hostname: "10 mail.example.com."
                mx_listesi.append(deger.rstrip("."))

    return mx_listesi


def _ns_sorgula(domain: str) -> list:
    """NS (name server) kayıtlarını nslookup ile sorgular."""
    satirlar = _nslookup_calistir(domain, "NS")
    ns_listesi = []

    for satir in satirlar:
        # "nameserver = ns1.example.com."
        if "nameserver" in satir.lower():
            parcalar = satir.split("=")
            if len(parcalar) > 1:
                ns_listesi.append(parcalar[1].strip().rstrip("."))

    return ns_listesi


def _txt_sorgula(domain: str) -> list:
    """TXT kayıtlarını nslookup ile sorgular."""
    satirlar = _nslookup_calistir(domain, "TXT")
    txt_listesi = []

    for satir in satirlar:
        # TXT kayıtları tırnak içinde gelir
        if '"' in satir:
            # Tırnak içindeki değeri çıkar
            eslesme = re.findall(r'"([^"]+)"', satir)
            txt_listesi.extend(eslesme)

    return txt_listesi


def dns_kesif(domain: str) -> DNSSonuc:
    """
    Hedef domain için kapsamlı DNS keşfi yapar.

    Args:
        domain: Sorgulanacak domain adı (örn: "google.com")

    Returns:
        DNSSonuc nesnesi.
    """
    # domain'den protokol varsa temizle
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.split("/")[0].strip()

    sonuc = DNSSonuc(domain=domain)

    # ── A / AAAA Kayıtları ────────────────────────────────────
    adres_sonuclari = _socket_a_kaydi(domain)
    if not adres_sonuclari:
        sonuc.hata = f"'{domain}' çözümlenemedi. DNS kaydı bulunamadı."
        return sonuc

    for tip, ip in adres_sonuclari:
        if tip == "A":
            sonuc.a_kayitlar.append(ip)
        else:
            sonuc.aaaa_kayitlar.append(ip)

    # ── MX Kayıtları ─────────────────────────────────────────
    sonuc.mx_kayitlar = _mx_sorgula(domain)

    # ── NS Kayıtları ─────────────────────────────────────────
    sonuc.ns_kayitlar = _ns_sorgula(domain)

    # ── TXT Kayıtları (SPF, DKIM, DMARC) ────────────────────
    sonuc.txt_kayitlar = _txt_sorgula(domain)

    # DMARC kaydı ayrı subdomain'de sorgulanır
    dmarc_txt = _txt_sorgula(f"_dmarc.{domain}")

    # SPF ve DMARC tespiti
    for kayit in sonuc.txt_kayitlar:
        if kayit.lower().startswith("v=spf"):
            sonuc.spf_var = True
    for kayit in dmarc_txt:
        if "v=dmarc" in kayit.lower():
            sonuc.dmarc_var = True
            sonuc.txt_kayitlar.append(f"[DMARC] {kayit}")

    # ── Güvenlik Bulguları ────────────────────────────────────
    if not sonuc.mx_kayitlar:
        sonuc.bulgular.append(("BILGI", "MX kaydı bulunamadı — mail sunucusu yok"))

    if not sonuc.spf_var and sonuc.mx_kayitlar:
        sonuc.bulgular.append((
            "ORTA",
            "SPF kaydı eksik! E-posta sahteciliğine (spoofing) açık olabilir."
        ))

    if not sonuc.dmarc_var and sonuc.mx_kayitlar:
        sonuc.bulgular.append((
            "ORTA",
            "DMARC politikası eksik! Phishing saldırılarına karşı savunmasız."
        ))

    if len(sonuc.a_kayitlar) > 3:
        sonuc.bulgular.append((
            "BILGI",
            f"Yük dengeleme tespit edildi — {len(sonuc.a_kayitlar)} farklı IP"
        ))

    return sonuc
