"""
=============================================================
  NetSentinel — HTML Rapor Üretici
  ─────────────────────────────────────────────────────────
  Görev:
    Tüm modüllerden gelen sonuçları alır ve profesyonel
    görünümlü bir HTML raporu + JSON raporu üretir.

    HTML raporu tarayıcıda açılabilir, paylaşılabilir.
    JSON raporu CI/CD pipeline'lara entegre edilebilir.
=============================================================
"""

import json
import datetime
import os
from typing import Optional


# ── Renk Paleti (Bulgu Seviyeleri) ─────────────────────────
SEVIYE_RENK = {
    "KRITIK": "#e74c3c",
    "YUKSEK": "#e67e22",
    "ORTA"  : "#f1c40f",
    "DUSUK" : "#3498db",
    "BILGI" : "#95a5a6",
    "TAMAM" : "#2ecc71",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetSentinel Raporu — {hedef}</title>
<style>
  :root {{
    --bg: #0d1117; --card: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
    --green: #3fb950; --yellow: #d29922; --red: #f85149; --orange: #db6d28;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', monospace; background: var(--bg); color: var(--text); padding: 2rem; }}
  .header {{ border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
  .header h1 {{ font-size: 1.8rem; color: var(--accent); display: flex; align-items: center; gap: .5rem; }}
  .header .meta {{ color: var(--muted); font-size: .85rem; margin-top: .5rem; }}
  .header .target {{ font-size: 1.1rem; margin-top: .3rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.2rem; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; }}
  .card h2 {{ font-size: 1rem; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: .6rem; margin-bottom: .8rem; display: flex; align-items: center; gap: .4rem; }}
  .badge {{ display: inline-block; padding: .15rem .5rem; border-radius: 4px; font-size: .75rem; font-weight: 700; color: #fff; }}
  .badge-kritik {{ background: #e74c3c; }}
  .badge-yuksek {{ background: #e67e22; }}
  .badge-orta   {{ background: #d4a017; color: #000; }}
  .badge-dusuk  {{ background: #3498db; }}
  .badge-bilgi  {{ background: #555; }}
  .badge-tamam  {{ background: #2ecc71; color: #000; }}
  .port-row {{ display: flex; align-items: center; gap: .6rem; padding: .3rem 0; border-bottom: 1px solid var(--border); font-size: .88rem; }}
  .port-row:last-child {{ border-bottom: none; }}
  .port-num {{ font-weight: 700; color: var(--green); width: 50px; }}
  .service {{ color: var(--accent); width: 100px; }}
  .banner {{ color: var(--muted); font-size: .78rem; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .header-row {{ display: flex; justify-content: space-between; align-items: center; padding: .3rem 0; border-bottom: 1px solid var(--border); font-size: .85rem; }}
  .header-row:last-child {{ border-bottom: none; }}
  .hname {{ color: var(--muted); width: 230px; font-size: .8rem; }}
  .hvalue {{ color: var(--text); font-size: .78rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 200px; }}
  .dns-item {{ padding: .25rem 0; font-size: .85rem; border-bottom: 1px solid var(--border); }}
  .dns-item:last-child {{ border-bottom: none; }}
  .dns-label {{ color: var(--muted); font-size: .75rem; }}
  .finding {{ padding: .4rem .6rem; margin: .3rem 0; border-radius: 4px; font-size: .83rem; border-left: 3px solid; }}
  .finding-KRITIK {{ border-color: #e74c3c; background: rgba(231,76,60,.1); }}
  .finding-YUKSEK {{ border-color: #e67e22; background: rgba(230,126,34,.1); }}
  .finding-ORTA   {{ border-color: #d4a017; background: rgba(212,160,23,.1); }}
  .finding-DUSUK  {{ border-color: #3498db; background: rgba(52,152,219,.1); }}
  .finding-BILGI  {{ border-color: #555; background: rgba(85,85,85,.1); }}
  .score-bar {{ height: 8px; border-radius: 4px; background: var(--border); margin: .4rem 0; overflow: hidden; }}
  .score-fill {{ height: 100%; border-radius: 4px; transition: width .5s; }}
  .ssl-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: .4rem; font-size: .83rem; }}
  .ssl-item {{ padding: .3rem; background: rgba(255,255,255,.03); border-radius: 4px; }}
  .ssl-key {{ color: var(--muted); font-size: .75rem; }}
  .ssl-val {{ color: var(--text); }}
  .stat-row {{ display: flex; justify-content: space-between; padding: .25rem 0; font-size: .85rem; border-bottom: 1px solid var(--border); }}
  .stat-row:last-child {{ border-bottom: none; }}
  .empty {{ color: var(--muted); font-style: italic; font-size: .85rem; }}
  footer {{ text-align: center; color: var(--muted); font-size: .78rem; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border); }}
</style>
</head>
<body>

<div class="header">
  <h1>🛡️ NetSentinel Güvenlik Raporu</h1>
  <div class="target">🎯 Hedef: <strong>{hedef}</strong></div>
  <div class="meta">📅 {tarih} &nbsp;|&nbsp; ⚙️ NetSentinel v1.0</div>
</div>

<div class="grid">
{kartlar}
</div>

<footer>NetSentinel — Eğitim Amaçlı Güvenlik Analiz Aracı &nbsp;|&nbsp; Yalnızca izinli sistemlerde kullanın.</footer>
</body>
</html>
"""


def _seviye_badge(seviye: str) -> str:
    css = f"badge-{seviye.lower()}"
    return f'<span class="badge {css}">{seviye}</span>'


def _port_karti(port_sonuclari: list) -> str:
    if not port_sonuclari:
        return '<div class="card"><h2>🔍 Açık Portlar</h2><p class="empty">Açık port bulunamadı.</p></div>'

    satirlar = ""
    for p in port_sonuclari:
        banner_html = f'<span class="banner">{p.banner}</span>' if p.banner else ""
        satirlar += f"""
        <div class="port-row">
          <span class="port-num">{p.port}</span>
          <span class="service">{p.servis}</span>
          {banner_html}
        </div>"""

    return f"""
    <div class="card">
      <h2>🔍 Açık Portlar ({len(port_sonuclari)})</h2>
      {satirlar}
    </div>"""


def _ssl_karti(ssl_sonuc) -> str:
    if ssl_sonuc is None:
        return ""

    if ssl_sonuc.hata and not ssl_sonuc.gecerli:
        return f"""
        <div class="card">
          <h2>🔒 SSL/TLS Sertifikası</h2>
          <p class="empty">{ssl_sonuc.hata}</p>
        </div>"""

    # Kalan gün rengi
    if ssl_sonuc.kalan_gun is not None:
        if ssl_sonuc.kalan_gun < 0:
            gun_renk = "#e74c3c"
            gun_text = f"SÜRESİ DOLMUŞ ({abs(ssl_sonuc.kalan_gun)} gün önce)"
        elif ssl_sonuc.kalan_gun < 30:
            gun_renk = "#e67e22"
            gun_text = f"{ssl_sonuc.kalan_gun} gün kaldı ⚠️"
        else:
            gun_renk = "#3fb950"
            gun_text = f"{ssl_sonuc.kalan_gun} gün kaldı ✓"
    else:
        gun_renk = "#8b949e"
        gun_text = "?"

    bulgular_html = ""
    for seviye, mesaj in ssl_sonuc.uyarilar:
        bulgular_html += f'<div class="finding finding-{seviye}">{_seviye_badge(seviye)} {mesaj}</div>'

    san_html = ""
    if ssl_sonuc.san_listesi:
        san_html = f'<div class="ssl-item"><div class="ssl-key">SANs ({len(ssl_sonuc.san_listesi)})</div><div class="ssl-val">{", ".join(ssl_sonuc.san_listesi[:4])}{"..." if len(ssl_sonuc.san_listesi) > 4 else ""}</div></div>'

    return f"""
    <div class="card">
      <h2>🔒 SSL/TLS Sertifikası</h2>
      <div class="ssl-grid">
        <div class="ssl-item">
          <div class="ssl-key">Common Name</div>
          <div class="ssl-val">{ssl_sonuc.subject or "?"}</div>
        </div>
        <div class="ssl-item">
          <div class="ssl-key">Veren Kurum</div>
          <div class="ssl-val">{ssl_sonuc.issuer or "?"}</div>
        </div>
        <div class="ssl-item">
          <div class="ssl-key">TLS Versiyonu</div>
          <div class="ssl-val">{ssl_sonuc.tls_versiyonu or "?"}</div>
        </div>
        <div class="ssl-item">
          <div class="ssl-key">Geçerlilik</div>
          <div class="ssl-val" style="color:{gun_renk}">{gun_text}</div>
        </div>
        <div class="ssl-item">
          <div class="ssl-key">Cipher Suite</div>
          <div class="ssl-val" style="font-size:.75rem">{ssl_sonuc.sifreli_suite or "?"}</div>
        </div>
        <div class="ssl-item">
          <div class="ssl-key">Self-Signed</div>
          <div class="ssl-val">{"⚠️ Evet" if ssl_sonuc.self_signed else "✓ Hayır"}</div>
        </div>
        {san_html}
      </div>
      {bulgular_html}
    </div>"""


def _http_karti(http_sonuc) -> str:
    if http_sonuc is None:
        return ""

    if http_sonuc.hata:
        return f"""
        <div class="card">
          <h2>🌐 HTTP Güvenlik Başlıkları</h2>
          <p class="empty">{http_sonuc.hata}</p>
        </div>"""

    skor = http_sonuc.guvenlik_skoru
    skor_renk = "#3fb950" if skor >= 70 else "#d4a017" if skor >= 40 else "#e74c3c"

    baslik_satirlar = ""
    for baslik, deger in http_sonuc.guvenlik_basliklar.items():
        if deger:
            icon = "✓"
            renk = "#3fb950"
            deger_html = f'<span class="hvalue" title="{deger}">{deger[:35]}{"..." if len(deger) > 35 else ""}</span>'
        else:
            icon = "✗"
            renk = "#e74c3c"
            deger_html = '<span style="color:#555;font-size:.75rem">eksik</span>'

        baslik_satirlar += f"""
        <div class="header-row">
          <span class="hname"><span style="color:{renk}">{icon}</span> {baslik}</span>
          {deger_html}
        </div>"""

    bulgular_html = ""
    for seviye, mesaj in http_sonuc.bulgular:
        bulgular_html += f'<div class="finding finding-{seviye}">{_seviye_badge(seviye)} {mesaj}</div>'

    return f"""
    <div class="card">
      <h2>🌐 HTTP Güvenlik Başlıkları</h2>
      <div style="margin-bottom:.8rem">
        <div style="display:flex;justify-content:space-between;font-size:.85rem">
          <span>Güvenlik Skoru</span>
          <span style="color:{skor_renk};font-weight:700">{skor}/100</span>
        </div>
        <div class="score-bar">
          <div class="score-fill" style="width:{skor}%;background:{skor_renk}"></div>
        </div>
      </div>
      {baslik_satirlar}
      <div style="margin-top:.6rem">{bulgular_html}</div>
    </div>"""


def _dns_karti(dns_sonuc) -> str:
    if dns_sonuc is None:
        return ""

    if dns_sonuc.hata:
        return f"""
        <div class="card">
          <h2>📡 DNS Keşfi</h2>
          <p class="empty">{dns_sonuc.hata}</p>
        </div>"""

    def liste_html(baslik, liste, renk="#c9d1d9"):
        if not liste:
            return ""
        satirlar = "".join(f'<div class="dns-item" style="color:{renk}">{v}</div>' for v in liste)
        return f'<div class="dns-label">{baslik}</div>{satirlar}'

    bulgular_html = ""
    for seviye, mesaj in dns_sonuc.bulgular:
        bulgular_html += f'<div class="finding finding-{seviye}">{_seviye_badge(seviye)} {mesaj}</div>'

    return f"""
    <div class="card">
      <h2>📡 DNS Keşfi</h2>
      {liste_html("A Kayıtları (IPv4)", dns_sonuc.a_kayitlar, "#3fb950")}
      {liste_html("AAAA Kayıtları (IPv6)", dns_sonuc.aaaa_kayitlar, "#58a6ff")}
      {liste_html("MX Kayıtları (Mail)", dns_sonuc.mx_kayitlar, "#d29922")}
      {liste_html("NS Kayıtları (Name Server)", dns_sonuc.ns_kayitlar, "#a371f7")}
      <div class="stat-row" style="margin-top:.5rem">
        <span>SPF Kaydı</span>
        <span style="color:{'#3fb950' if dns_sonuc.spf_var else '#e74c3c'}">{'✓ Var' if dns_sonuc.spf_var else '✗ Yok'}</span>
      </div>
      <div class="stat-row">
        <span>DMARC Politikası</span>
        <span style="color:{'#3fb950' if dns_sonuc.dmarc_var else '#e74c3c'}">{'✓ Var' if dns_sonuc.dmarc_var else '✗ Yok'}</span>
      </div>
      {bulgular_html}
    </div>"""


def html_rapor_olustur(
    hedef       : str,
    port_sonuc  = None,
    ssl_sonuc   = None,
    http_sonuc  = None,
    dns_sonuc   = None,
    cikti_klasor: str = ".",
) -> str:
    """
    Tüm modül sonuçlarından HTML raporu üretir ve diske kaydeder.

    Returns:
        Oluşturulan HTML dosyasının yolu.
    """
    kartlar = ""
    if port_sonuc is not None:
        kartlar += _port_karti(port_sonuc)
    if ssl_sonuc is not None:
        kartlar += _ssl_karti(ssl_sonuc)
    if http_sonuc is not None:
        kartlar += _http_karti(http_sonuc)
    if dns_sonuc is not None:
        kartlar += _dns_karti(dns_sonuc)

    tarih_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = HTML_TEMPLATE.format(
        hedef=hedef,
        tarih=tarih_str,
        kartlar=kartlar,
    )

    dosya_adi = f"netsentinel_{hedef.replace('.', '_').replace('://', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    yol = os.path.join(cikti_klasor, dosya_adi)

    with open(yol, "w", encoding="utf-8") as f:
        f.write(html)

    return yol


def json_rapor_olustur(
    hedef       : str,
    port_sonuc  = None,
    ssl_sonuc   = None,
    http_sonuc  = None,
    dns_sonuc   = None,
    cikti_klasor: str = ".",
) -> str:
    """Sonuçları JSON formatında kaydeder."""
    veri = {
        "meta": {
            "hedef"  : hedef,
            "tarih"  : datetime.datetime.now().isoformat(),
            "arac"   : "NetSentinel v1.0",
        },
        "portlar": [
            {"port": p.port, "servis": p.servis, "banner": p.banner}
            for p in (port_sonuc or [])
        ],
        "ssl": {
            "gecerli"       : getattr(ssl_sonuc, "gecerli", False),
            "subject"       : getattr(ssl_sonuc, "subject", ""),
            "issuer"        : getattr(ssl_sonuc, "issuer", ""),
            "tls_versiyonu" : getattr(ssl_sonuc, "tls_versiyonu", ""),
            "kalan_gun"     : getattr(ssl_sonuc, "kalan_gun", None),
            "uyarilar"      : getattr(ssl_sonuc, "uyarilar", []),
        } if ssl_sonuc else None,
        "http_basliklar": {
            "guvenlik_skoru": getattr(http_sonuc, "guvenlik_skoru", 0),
            "bulgular"      : getattr(http_sonuc, "bulgular", []),
            "basliklar"     : getattr(http_sonuc, "guvenlik_basliklar", {}),
        } if http_sonuc else None,
        "dns": {
            "a_kayitlar" : getattr(dns_sonuc, "a_kayitlar", []),
            "mx_kayitlar": getattr(dns_sonuc, "mx_kayitlar", []),
            "ns_kayitlar": getattr(dns_sonuc, "ns_kayitlar", []),
            "spf_var"    : getattr(dns_sonuc, "spf_var", False),
            "dmarc_var"  : getattr(dns_sonuc, "dmarc_var", False),
            "bulgular"   : getattr(dns_sonuc, "bulgular", []),
        } if dns_sonuc else None,
    }

    dosya_adi = f"netsentinel_{hedef.replace('.', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    yol = os.path.join(cikti_klasor, dosya_adi)

    with open(yol, "w", encoding="utf-8") as f:
        json.dump(veri, f, indent=2, ensure_ascii=False, default=str)

    return yol
