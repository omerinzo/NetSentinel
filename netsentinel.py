"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ███╗   ██╗███████╗████████╗███████╗███████╗███╗   ██╗     ║
║   ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝████╗  ██║     ║
║   ██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██╔██╗ ██║     ║
║   ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║╚██╗██║     ║
║   ██║ ╚████║███████╗   ██║   ███████║███████╗██║ ╚████║     ║
║   ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝    ║
║                                                              ║
║   S E N T I N E L                                            ║
║   Çok Modüllü Ağ Güvenlik Keşif Aracı                       ║
║   ─────────────────────────────────────────────────────────  ║
║   Modüller:                                                  ║
║     [1] Port Tarayıcı + Banner Grabbing                      ║
║     [2] SSL/TLS Sertifika Analizörü                          ║
║     [3] HTTP Güvenlik Başlıkları Denetçisi                   ║
║     [4] DNS Keşif Motoru                                     ║
║     [5] HTML + JSON Rapor Üretici                            ║
╚══════════════════════════════════════════════════════════════╝

  YASAL UYARI:
  Bu araç yalnızca izin verilen sistemlerde ve eğitim
  amaçlı kullanım için tasarlanmıştır. İzinsiz tarama
  birçok ülkede yasal suç kapsamına girer.

  Test için: scanme.nmap.org (Nmap'in resmi test sunucusu)
"""

import sys
import io
import os
import argparse
import datetime
import socket

# Windows UTF-8 terminal düzeltmesi
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Modülleri import et
from modules.port_scanner import port_tara, PORT_GRUPLARI
from modules.ssl_check    import ssl_analiz
from modules.http_headers import http_baslik_analiz
from modules.dns_recon    import dns_kesif
from modules.reporter     import html_rapor_olustur, json_rapor_olustur


# ── Renk Kodu Kısaltmaları ──────────────────────────────────
class C:
    R = "\033[91m"   # kırmızı
    G = "\033[92m"   # yeşil
    Y = "\033[93m"   # sarı
    B = "\033[94m"   # mavi
    M = "\033[95m"   # magenta
    C = "\033[96m"   # cyan
    D = "\033[90m"   # gri/dim
    S = "\033[0m"    # sıfırla
    K = "\033[1m"    # kalın


BANNER = f"""
{C.C}{C.K}
  ███╗   ██╗███████╗████████╗███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
  ██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
  ██║ ╚████║███████╗   ██║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
{C.S}{C.D}  Çok Modüllü Ağ Güvenlik Keşif Aracı  |  v1.0  |  Yalnızca İzinli Sistemlerde Kullanın{C.S}
"""


def bolum_yaz(baslik: str, emoji: str = ""):
    """Terminalde görsel bölüm başlığı basar."""
    cizgi = "─" * 62
    print(f"\n{C.B}{C.K}{cizgi}")
    print(f"  {emoji}  {baslik}")
    print(f"{cizgi}{C.S}")


def seviye_renk(seviye: str) -> str:
    """Bulgu seviyesine göre ANSI rengi döndürür."""
    return {
        "KRITIK": C.R, "YUKSEK": C.Y, "ORTA": C.Y,
        "DUSUK" : C.B, "BILGI" : C.D, "TAMAM": C.G,
    }.get(seviye, C.S)


# ─────────────────────────────────────────────
#  Modül Çıktı Fonksiyonları
# ─────────────────────────────────────────────

def port_cikti_yazdir(sonuclar: list):
    """Port tarama sonuçlarını tabloya döker."""
    if not sonuclar:
        print(f"  {C.D}Açık port bulunamadı.{C.S}")
        return

    print(f"  {C.K}{'PORT':<8} {'SERVİS':<16} {'BANNER'}{C.S}")
    print(f"  {'─'*8} {'─'*16} {'─'*35}")

    for p in sonuclar:
        banner = p.banner[:50] + "..." if len(p.banner) > 50 else p.banner
        print(f"  {C.G}{p.port:<8}{C.S} {C.C}{p.servis:<16}{C.S} {C.D}{banner}{C.S}")

    print(f"\n  {C.K}Toplam:{C.S} {C.G}{len(sonuclar)} açık port{C.S}")


def ssl_cikti_yazdir(sonuc):
    """SSL analiz sonucunu ekrana basar."""
    if sonuc.hata and not sonuc.gecerli:
        print(f"  {C.R}[HATA]{C.S} {sonuc.hata}")
        return

    print(f"  {'Alan Adı':<22}: {C.C}{sonuc.subject}{C.S}")
    print(f"  {'Veren Kurum':<22}: {sonuc.issuer}")
    print(f"  {'TLS Versiyonu':<22}: {C.G if 'TLSv1.3' in sonuc.tls_versiyonu else C.Y}{sonuc.tls_versiyonu}{C.S}")
    print(f"  {'Cipher Suite':<22}: {C.D}{sonuc.sifreli_suite}{C.S}")
    print(f"  {'Öz-İmzalı':<22}: {C.R+'Evet' if sonuc.self_signed else C.G+'Hayır'}{C.S}")

    if sonuc.kalan_gun is not None:
        if sonuc.kalan_gun < 0:
            gun_str = f"{C.R}SÜRESİ DOLMUŞ ({abs(sonuc.kalan_gun)} gün önce){C.S}"
        elif sonuc.kalan_gun < 30:
            gun_str = f"{C.Y}{sonuc.kalan_gun} gün kaldı{C.S}"
        else:
            gun_str = f"{C.G}{sonuc.kalan_gun} gün kaldı{C.S}"
        print(f"  {'Kalan Süre':<22}: {gun_str}")

    if sonuc.uyarilar:
        print(f"\n  {C.K}Uyarılar:{C.S}")
        for seviye, mesaj in sonuc.uyarilar:
            renk = seviye_renk(seviye)
            print(f"    {renk}[{seviye}]{C.S} {mesaj}")


def http_cikti_yazdir(sonuc):
    """HTTP başlıkları analiz sonucunu ekrana basar."""
    if sonuc.hata:
        print(f"  {C.R}[HATA]{C.S} {sonuc.hata}")
        return

    skor = sonuc.guvenlik_skoru
    skor_renk = C.G if skor >= 70 else C.Y if skor >= 40 else C.R
    print(f"  Güvenlik Skoru: {skor_renk}{C.K}{skor}/100{C.S}\n")

    print(f"  {C.K}{'BAŞLIK':<38} {'DURUM'}{C.S}")
    print(f"  {'─'*38} {'─'*8}")

    for baslik, deger in sonuc.guvenlik_basliklar.items():
        if deger:
            print(f"  {C.G}✓{C.S} {baslik:<36} {C.G}Var{C.S}")
        else:
            print(f"  {C.R}✗{C.S} {baslik:<36} {C.R}Eksik{C.S}")

    if sonuc.bulgular:
        print(f"\n  {C.K}Bulgular:{C.S}")
        for seviye, mesaj in sonuc.bulgular:
            renk = seviye_renk(seviye)
            print(f"    {renk}[{seviye}]{C.S} {mesaj}")


def dns_cikti_yazdir(sonuc):
    """DNS keşif sonuçlarını ekrana basar."""
    if sonuc.hata:
        print(f"  {C.R}[HATA]{C.S} {sonuc.hata}")
        return

    def liste_yaz(baslik, liste, renk=C.S):
        if liste:
            print(f"  {C.K}{baslik}:{C.S}")
            for item in liste:
                print(f"    {renk}{item}{C.S}")

    liste_yaz("A Kayıtları (IPv4)", sonuc.a_kayitlar, C.G)
    liste_yaz("AAAA Kayıtları (IPv6)", sonuc.aaaa_kayitlar, C.B)
    liste_yaz("MX Kayıtları (Mail)", sonuc.mx_kayitlar, C.Y)
    liste_yaz("NS Kayıtları", sonuc.ns_kayitlar, C.M)

    print(f"\n  SPF Kaydı  : {C.G+'✓ Var' if sonuc.spf_var  else C.R+'✗ Yok'}{C.S}")
    print(f"  DMARC      : {C.G+'✓ Var' if sonuc.dmarc_var else C.R+'✗ Yok'}{C.S}")

    if sonuc.bulgular:
        print(f"\n  {C.K}Bulgular:{C.S}")
        for seviye, mesaj in sonuc.bulgular:
            renk = seviye_renk(seviye)
            print(f"    {renk}[{seviye}]{C.S} {mesaj}")


# ─────────────────────────────────────────────
#  Ana Tarama Fonksiyonu
# ─────────────────────────────────────────────

def tara(args):
    """Tüm modülleri koordine eder ve ekrana basar."""

    hedef = args.hedef
    print(BANNER)

    print(f"  {C.K}Hedef   :{C.S} {C.C}{hedef}{C.S}")
    print(f"  {C.K}Başlangıç:{C.S} {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # IP çözümleme
    try:
        ip = socket.gethostbyname(hedef)
        if ip != hedef:
            print(f"  {C.K}IP      :{C.S} {C.D}{ip}{C.S}")
    except socket.gaierror:
        print(f"\n  {C.R}[HATA]{C.S} '{hedef}' çözümlenemedi!")
        sys.exit(1)

    port_sonuclari = None
    ssl_sonucu     = None
    http_sonucu    = None
    dns_sonucu     = None

    # ── 1. Port Tarama ────────────────────────────────────────
    if not args.skip_port:
        bolum_yaz("PORT TARAMA + BANNER GRABBING", "🔍")

        # Port listesi belirle
        if args.portlar:
            portlar = []
            for p in args.portlar.split(","):
                p = p.strip()
                if "-" in p:
                    a, b = p.split("-")
                    portlar.extend(range(int(a), int(b)+1))
                else:
                    portlar.append(int(p))
        elif args.port_grubu:
            portlar = PORT_GRUPLARI.get(args.port_grubu, PORT_GRUPLARI["hizli"])
        else:
            portlar = PORT_GRUPLARI["hizli"]

        print(f"  {C.D}{len(portlar)} port taranıyor...{C.S}\n")
        port_sonuclari = port_tara(
            hedef=ip, portlar=portlar,
            timeout=args.timeout, max_thread=args.thread
        )
        port_cikti_yazdir(port_sonuclari)

    # ── 2. SSL Analizi ────────────────────────────────────────
    if not args.skip_ssl:
        bolum_yaz("SSL/TLS SERTİFİKA ANALİZİ", "🔒")
        ssl_portu = 443
        print(f"  {C.D}Port {ssl_portu} üzerinde SSL analiz ediliyor...{C.S}\n")
        ssl_sonucu = ssl_analiz(hedef, port=ssl_portu, timeout=args.timeout + 2)
        ssl_cikti_yazdir(ssl_sonucu)

    # ── 3. HTTP Başlıkları ────────────────────────────────────
    if not args.skip_http:
        bolum_yaz("HTTP GÜVENLİK BAŞLIKLARI", "🌐")
        url = f"https://{hedef}"
        print(f"  {C.D}{url} analiz ediliyor...{C.S}\n")
        http_sonucu = http_baslik_analiz(url, timeout=args.timeout + 3)
        http_cikti_yazdir(http_sonucu)

    # ── 4. DNS Keşfi ──────────────────────────────────────────
    if not args.skip_dns:
        bolum_yaz("DNS KEŞİF MOTORU", "📡")
        print(f"  {C.D}DNS kayıtları sorgulanıyor...{C.S}\n")
        dns_sonucu = dns_kesif(hedef)
        dns_cikti_yazdir(dns_sonucu)

    # ── 5. Rapor Oluştur ──────────────────────────────────────
    if args.html or args.json_rapor:
        bolum_yaz("RAPOR OLUŞTURULUYOR", "📊")

        cikti_dir = args.cikti or "."
        os.makedirs(cikti_dir, exist_ok=True)

        if args.html:
            html_yol = html_rapor_olustur(
                hedef=hedef,
                port_sonuc=port_sonuclari,
                ssl_sonuc=ssl_sonucu,
                http_sonuc=http_sonucu,
                dns_sonuc=dns_sonucu,
                cikti_klasor=cikti_dir,
            )
            print(f"  {C.G}[HTML]{C.S} Rapor oluşturuldu: {C.C}{html_yol}{C.S}")

        if args.json_rapor:
            json_yol = json_rapor_olustur(
                hedef=hedef,
                port_sonuc=port_sonuclari,
                ssl_sonuc=ssl_sonucu,
                http_sonuc=http_sonucu,
                dns_sonuc=dns_sonucu,
                cikti_klasor=cikti_dir,
            )
            print(f"  {C.G}[JSON]{C.S} Rapor oluşturuldu: {C.C}{json_yol}{C.S}")

    # ── Özet ──────────────────────────────────────────────────
    print(f"\n{C.B}{C.K}{'═'*62}{C.S}")
    print(f"  Tarama tamamlandı — {datetime.datetime.now().strftime('%H:%M:%S')}")
    print(f"{C.B}{C.K}{'═'*62}{C.S}\n")


# ─────────────────────────────────────────────
#  Komut Satırı Arayüzü
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="netsentinel",
        description="NetSentinel — Çok Modüllü Ağ Güvenlik Keşif Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Kullanim Ornekleri:
  python netsentinel.py tara --hedef scanme.nmap.org
  python netsentinel.py tara --hedef google.com --html --json
  python netsentinel.py tara --hedef 192.168.1.1 --portlar 22,80,443,8080
  python netsentinel.py tara --hedef example.com --port-grubu web --skip-dns
  python netsentinel.py tara --hedef example.com --html --cikti ./raporlar

Port Gruplari:
  hizli      : 21,22,25,53,80,110,143,443,445,3306,3389,8080
  web        : 80,443,8080,8443,8888,3000,4000,5000
  veritabani : 1433,1521,3306,5432,6379,9200,27017
  tam        : 1-1024 (tüm standart portlar)
        """
    )

    alt = parser.add_subparsers(dest="komut", metavar="<komut>")

    tara_p = alt.add_parser("tara", help="Hedefi tüm modüllerle analiz et")

    tara_p.add_argument("--hedef",      "-H", required=True,  metavar="HEDEF",
                        help="IP adresi veya hostname")
    tara_p.add_argument("--portlar",    "-p", default=None,   metavar="PORTLAR",
                        help="Port listesi: '22,80,443' veya '1-1024'")
    tara_p.add_argument("--port-grubu", "-g", default=None,   metavar="GRUP",
                        choices=list(PORT_GRUPLARI.keys()),
                        help="Port grubu: hizli, web, veritabani, tam")
    tara_p.add_argument("--timeout",    "-t", type=float, default=1.5, metavar="SN",
                        help="Zaman aşımı (varsayılan: 1.5 sn)")
    tara_p.add_argument("--thread",     "-T", type=int,   default=100, metavar="N",
                        help="Paralel thread sayısı (varsayılan: 100)")
    tara_p.add_argument("--html",       action="store_true",
                        help="HTML raporu oluştur")
    tara_p.add_argument("--json",  dest="json_rapor", action="store_true",
                        help="JSON raporu oluştur")
    tara_p.add_argument("--cikti",      default="raporlar", metavar="KLASOR",
                        help="Rapor çıktı klasörü (varsayılan: raporlar/)")
    tara_p.add_argument("--skip-port",  action="store_true", help="Port taramayı atla")
    tara_p.add_argument("--skip-ssl",   action="store_true", help="SSL analizini atla")
    tara_p.add_argument("--skip-http",  action="store_true", help="HTTP başlık analizini atla")
    tara_p.add_argument("--skip-dns",   action="store_true", help="DNS keşfini atla")

    args = parser.parse_args()

    if args.komut == "tara":
        tara(args)
    else:
        print(BANNER)
        parser.print_help()


if __name__ == "__main__":
    main()
