"""
=============================================================
  NetSentinel — HTTP Güvenlik Başlıkları Denetçisi
  ─────────────────────────────────────────────────────────
  Görev:
    Web sunucusunun HTTP yanıt başlıklarını analiz eder.
    Eksik güvenlik başlıkları pek çok yaygın web saldırısına
    (XSS, Clickjacking, MIME Sniffing vb.) zemin hazırlar.

  Kontrol Edilen Başlıklar:
    ├─ Strict-Transport-Security (HSTS)  → HTTPS zorlama
    ├─ Content-Security-Policy   (CSP)   → XSS koruması
    ├─ X-Frame-Options                   → Clickjacking koruması
    ├─ X-Content-Type-Options            → MIME sniffing engeli
    ├─ Referrer-Policy                   → URL sızıntısı engeli
    ├─ Permissions-Policy                → Tarayıcı API kısıtlaması
    └─ Server                            → Sürüm bilgisi ifşası
=============================================================
"""

import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass, field


@dataclass
class BaslikSonuc:
    """HTTP güvenlik başlıkları denetim sonucu."""
    url          : str
    durum_kodu   : int  = 0
    hata         : str  = ""
    sunucu_bilgisi: str = ""      # Server başlığı (versiyon ifşası)
    tum_basliklar: dict = field(default_factory=dict)

    # Güvenlik başlıkları: { başlık_adı: değer veya None }
    guvenlik_basliklar: dict = field(default_factory=dict)

    # Bulgu listesi: [ (seviye, açıklama) ]
    bulgular     : list = field(default_factory=list)

    # Genel skor: 0-100
    guvenlik_skoru: int = 0


# Kontrol edilecek başlıklar ve açıklamaları
GUVENLIK_BASLIKLAR = {
    "Strict-Transport-Security": {
        "aciklama": "HTTPS bağlantısını zorla (HSTS)",
        "kritik"  : True,
        "ornek"   : "max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "aciklama": "İzin verilen içerik kaynaklarını sınırla (XSS koruması)",
        "kritik"  : True,
        "ornek"   : "default-src 'self'",
    },
    "X-Frame-Options": {
        "aciklama": "Sayfanın iframe içinde açılmasını engelle (Clickjacking)",
        "kritik"  : True,
        "ornek"   : "DENY veya SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "aciklama": "Tarayıcının dosya türünü tahmin etmesini engelle (MIME Sniffing)",
        "kritik"  : False,
        "ornek"   : "nosniff",
    },
    "Referrer-Policy": {
        "aciklama": "URL bilgisinin üçüncü taraflara sızmasını kontrol et",
        "kritik"  : False,
        "ornek"   : "no-referrer veya strict-origin",
    },
    "Permissions-Policy": {
        "aciklama": "Kamera, mikrofon, konum gibi API erişimlerini kısıtla",
        "kritik"  : False,
        "ornek"   : "camera=(), microphone=(), geolocation=()",
    },
    "X-XSS-Protection": {
        "aciklama": "Eski tarayıcılarda XSS filtresi (modern tarayıcılarda CSP tercih edilir)",
        "kritik"  : False,
        "ornek"   : "1; mode=block",
    },
}


def http_baslik_analiz(url: str, timeout: float = 8.0) -> BaslikSonuc:
    """
    Verilen URL'e HEAD isteği göndererek HTTP başlıklarını analiz eder.

    HEAD isteği → GET gibidir ama yanıt gövdesi (body) gelmez.
    Sadece başlıkları almak için idealdir, çok hızlıdır.

    Args:
        url     : Analiz edilecek URL (http:// veya https://).
        timeout : İstek zaman aşımı.

    Returns:
        BaslikSonuc nesnesi.
    """
    sonuc = BaslikSonuc(url=url)

    # URL'de protokol yoksa https ekle
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
        sonuc.url = url

    try:
        # SSL doğrulamasını devre dışı bırak (test amaçlı)
        # Gerçek üretim ortamında bu yapılmamalı!
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        # HEAD isteği gönder
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent",
                       "NetSentinel/1.0 Security Scanner")

        with urllib.request.urlopen(req, timeout=timeout,
                                    context=ssl_ctx) as yanit:
            sonuc.durum_kodu = yanit.getcode()

            # Tüm başlıkları sözlüğe al
            sonuc.tum_basliklar = dict(yanit.headers.items())

    except urllib.error.HTTPError as e:
        # 4xx/5xx hatalar da başlık içerir
        sonuc.durum_kodu = e.code
        sonuc.tum_basliklar = dict(e.headers.items())

    except urllib.error.URLError as e:
        sonuc.hata = f"Bağlantı hatası: {str(e.reason)[:80]}"
        return sonuc

    except Exception as e:
        sonuc.hata = f"Beklenmedik hata: {str(e)[:80]}"
        return sonuc

    # Başlıkları büyük/küçük harf duyarsız ara
    basliklar_lower = {k.lower(): v for k, v in sonuc.tum_basliklar.items()}

    # Server başlığı kontrolü (versiyon bilgisi ifşası)
    server = basliklar_lower.get("server", "")
    sonuc.sunucu_bilgisi = server
    if server:
        # Versiyon numarası içeriyorsa uyar (nginx/1.18.0 gibi)
        import re
        if re.search(r"\d+\.\d+", server):
            sonuc.bulgular.append((
                "ORTA",
                f"Server başlığı versiyon ifşa ediyor: {server}"
            ))

    # Her güvenlik başlığını kontrol et
    puan = 100
    for baslik_adi, bilgi in GUVENLIK_BASLIKLAR.items():
        deger = basliklar_lower.get(baslik_adi.lower())
        sonuc.guvenlik_basliklar[baslik_adi] = deger

        if deger is None:
            # Başlık eksik!
            if bilgi["kritik"]:
                sonuc.bulgular.append((
                    "YUKSEK",
                    f"Eksik kritik başlık: {baslik_adi} — {bilgi['aciklama']}"
                ))
                puan -= 15
            else:
                sonuc.bulgular.append((
                    "DUSUK",
                    f"Eksik başlık: {baslik_adi} — {bilgi['aciklama']}"
                ))
                puan -= 5

    sonuc.guvenlik_skoru = max(0, puan)
    return sonuc
