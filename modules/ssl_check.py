"""
=============================================================
  NetSentinel — SSL/TLS Sertifika Analizörü
  ─────────────────────────────────────────────────────────
  Görev:
    Hedef sunucunun SSL/TLS sertifikasını inceler ve
    aşağıdaki güvenlik sorunlarını raporlar:

    ✓ Sertifika geçerlilik tarihleri (süresi dolmuş mu?)
    ✓ Kalan gün sayısı
    ✓ Sertifika veren kurum (issuer)
    ✓ Konu bilgisi (common name, SANs)
    ✓ TLS protokol versiyonu (TLS 1.0/1.1 = zayıf!)
    ✓ Şifreleme algoritması (cipher suite)
    ✓ Self-signed (öz imzalı) sertifika tespiti

  SSL/TLS Neden Önemli?
    HTTPS bağlantısında tüm veri şifrelenir. Ancak yanlış
    yapılandırılmış sertifikalar man-in-the-middle (MITM)
    saldırılarına kapı açabilir.
=============================================================
"""

import ssl
import socket
import datetime
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SSLSonuc:
    """SSL/TLS analiz sonucunu tutar."""
    host            : str
    port            : int
    gecerli         : bool = False          # Bağlantı kurulabildi mi?
    hata            : str  = ""

    # Sertifika bilgileri
    subject         : str  = ""            # CN (common name)
    issuer          : str  = ""            # Sertifika veren kurum
    san_listesi     : list = field(default_factory=list)   # Subject Alt Names
    baslangic_tarihi: Optional[datetime.datetime] = None
    bitis_tarihi    : Optional[datetime.datetime] = None
    kalan_gun       : Optional[int] = None

    # TLS detayları
    tls_versiyonu   : str  = ""            # TLS 1.2, TLS 1.3 vb.
    sifreli_suite   : str  = ""            # Cipher suite adı
    self_signed     : bool = False         # Öz-imzalı mı?

    # Güvenlik uyarıları
    uyarilar        : list = field(default_factory=list)


def _parse_tarih(tarih_str: str) -> datetime.datetime:
    """
    ASN.1 tarih formatını Python datetime'a çevirir.
    SSL sertifikalarında tarihler 'Mmm DD HH:MM:SS YYYY GMT' formatındadır.
    """
    try:
        return datetime.datetime.strptime(tarih_str, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return datetime.datetime.strptime(tarih_str, "%Y%m%d%H%M%SZ")


def _dict_deger(d: dict, anahtar: str) -> str:
    """
    SSL sertifika dict'inden (nested tuple yapısı) değer çeker.
    Örn: (('commonName', 'example.com'),) → 'example.com'
    """
    for tuple_grup in d:
        for k, v in tuple_grup:
            if k == anahtar:
                return v
    return ""


def ssl_analiz(host: str, port: int = 443, timeout: float = 5.0) -> SSLSonuc:
    """
    Verilen host:port'a SSL bağlantısı kurarak sertifikayı analiz eder.

    Python'un ssl modülü, bağlantı kurulduğunda sunucunun
    sertifikasını otomatik olarak doğrular ve parse eder.

    Args:
        host    : Hedef hostname (IP değil, hostname olmalı).
        port    : SSL portu (varsayılan: 443).
        timeout : Bağlantı zaman aşımı.

    Returns:
        SSLSonuc nesnesi.
    """
    sonuc = SSLSonuc(host=host, port=port)

    try:
        # SSL context oluştur — sunucu sertifikasını doğrulayan ayar
        ctx = ssl.create_default_context()

        # Bağlantıyı kur
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssl_sock:

                sonuc.gecerli = True

                # TLS versiyonu (TLS 1.3, TLS 1.2, vb.)
                sonuc.tls_versiyonu = ssl_sock.version() or "Bilinmiyor"

                # Cipher suite (şifreleme algoritması)
                cipher = ssl_sock.cipher()
                if cipher:
                    sonuc.sifreli_suite = cipher[0]   # Örn: AES256-GCM-SHA384

                # Sertifika bilgilerini al
                cert = ssl_sock.getpeercert()

                # Common Name (CN) — genellikle domain adı
                subject = dict(x[0] for x in cert.get("subject", []))
                sonuc.subject = subject.get("commonName", "")

                # Issuer (veren kurum)
                issuer = dict(x[0] for x in cert.get("issuer", []))
                sonuc.issuer = issuer.get("organizationName", "")

                # Subject Alternative Names (SANs) — tüm geçerli domainler
                san_raw = cert.get("subjectAltName", [])
                sonuc.san_listesi = [v for t, v in san_raw if t == "DNS"]

                # Geçerlilik tarihleri
                not_before = cert.get("notBefore", "")
                not_after  = cert.get("notAfter", "")

                if not_before:
                    sonuc.baslangic_tarihi = _parse_tarih(not_before)
                if not_after:
                    sonuc.bitis_tarihi = _parse_tarih(not_after)
                    kalan = sonuc.bitis_tarihi - datetime.datetime.utcnow()
                    sonuc.kalan_gun = kalan.days

                # Self-signed kontrolü: issuer == subject ise öz-imzalı
                subj_org = subject.get("organizationName", "")
                issue_org = issuer.get("organizationName", "")
                sonuc.self_signed = (subj_org == issue_org and bool(subj_org))

    except ssl.SSLCertVerificationError as e:
        # Sertifika doğrulanamadı (expired, self-signed, vs.)
        sonuc.hata = f"SSL doğrulama hatası: {e.reason}"
        # Yine de bilgileri almaya çalış (doğrulama olmadan)
        _ssl_dogrulamasiz_oku(host, port, timeout, sonuc)

    except ssl.SSLError as e:
        sonuc.hata = f"SSL hatası: {str(e)[:80]}"

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        sonuc.hata = f"Bağlantı hatası: {str(e)[:80]}"

    # Güvenlik uyarıları üret
    _uyan_kontrol(sonuc)

    return sonuc


def _ssl_dogrulamasiz_oku(host, port, timeout, sonuc: SSLSonuc):
    """
    Sertifika doğrulaması olmadan bağlanarak ham bilgileri okur.
    Bozuk/expired sertifikalarda temel bilgileri kurtarır.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssl_sock:
                sonuc.tls_versiyonu = ssl_sock.version() or ""
                cipher = ssl_sock.cipher()
                if cipher:
                    sonuc.sifreli_suite = cipher[0]
                cert = ssl_sock.getpeercert(binary_form=False)
    except Exception:
        pass


def _uyan_kontrol(sonuc: SSLSonuc):
    """
    Analiz sonucuna göre güvenlik uyarıları üretir.
    """
    uyarilar = []

    # Süresi dolmuş sertifika
    if sonuc.kalan_gun is not None:
        if sonuc.kalan_gun < 0:
            uyarilar.append(("KRITIK", f"Sertifika {abs(sonuc.kalan_gun)} gün önce süresi doldu!"))
        elif sonuc.kalan_gun < 14:
            uyarilar.append(("YUKSEK", f"Sertifika {sonuc.kalan_gun} gün içinde sona eriyor!"))
        elif sonuc.kalan_gun < 30:
            uyarilar.append(("ORTA", f"Sertifika yakında sona eriyor ({sonuc.kalan_gun} gün)"))

    # Zayıf TLS versiyonu
    if sonuc.tls_versiyonu in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        uyarilar.append(("YUKSEK", f"Zayıf TLS versiyonu kullanılıyor: {sonuc.tls_versiyonu}"))

    # Öz-imzalı sertifika
    if sonuc.self_signed:
        uyarilar.append(("ORTA", "Öz-imzalı sertifika tespit edildi"))

    # Hata varsa
    if sonuc.hata:
        uyarilar.append(("YUKSEK", sonuc.hata))

    sonuc.uyarilar = uyarilar
