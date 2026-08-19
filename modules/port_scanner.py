"""
=============================================================
  NetSentinel — Port Tarayıcı + Banner Grabbing Modülü
  ─────────────────────────────────────────────────────────
  Görev:
    Hedef sunucunun belirli portlarına TCP bağlantısı kurar.
    Açık portlarda "banner grabbing" yapar — yani sunucunun
    kendini tanıttığı ilk mesajı okur (örn: "SSH-2.0-OpenSSH").
    Bu sayede sadece portun açık olduğunu değil, üzerinde
    hangi yazılımın çalıştığını da öğreniriz.

  Banner Grabbing Nedir?
    Birçok servis bağlantı kurulduğunda otomatik olarak
    bir karşılama mesajı gönderir. Bu mesaj genellikle
    yazılım adı ve versiyonunu içerir. Saldırganlar bunu
    hedef sistemin zafiyetlerini bulmak için kullanır.
    Savunmacılar ise kendi sistemlerini test etmek için.
=============================================================
"""

import socket
import threading
import queue
from dataclasses import dataclass, field
from typing import Optional


# ── Yaygın Portlar & Servis Adları ──────────────────────────
SERVICE_DB = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP-TLS", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    2181: "Zookeeper", 3306: "MySQL", 3389: "RDP",
    4444: "Metasploit", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 6443: "Kubernetes", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "Jupyter", 9200: "Elasticsearch",
    27017: "MongoDB", 50070: "Hadoop",
}

# Sık taranan port grupları
PORT_GRUPLARI = {
    "hizli"  : [21,22,23,25,53,80,110,143,443,445,3306,3389,8080],
    "web"    : [80,443,8080,8443,8888,3000,4000,5000,9000],
    "veritabani": [1433,1521,3306,5432,6379,9200,27017],
    "tam"    : list(range(1, 1025)),   # İlk 1024 port (standart)
}


@dataclass
class PortSonuc:
    """Tek bir port tarama sonucunu temsil eder."""
    port    : int
    acik    : bool
    servis  : str = ""
    banner  : str = ""        # Sunucudan alınan ilk mesaj
    hata    : str = ""


def banner_yakala(sock: socket.socket, port: int, timeout: float) -> str:
    """
    Açık porttan banner (tanıtım mesajı) okur.

    HTTP portları için GET isteği göndeririz çünkü HTTP
    sunucuları bağlantıda otomatik mesaj göndermez.
    Diğer servisler (SSH, FTP, SMTP) kendiliğinden konuşur.

    Args:
        sock    : Bağlantı kurulmuş socket nesnesi.
        port    : Port numarası (HTTP/HTTPS tespiti için).
        timeout : Okuma zaman aşımı.

    Returns:
        Banner metni (temizlenmiş) veya boş string.
    """
    try:
        sock.settimeout(timeout)

        # HTTP portlarında GET isteği gönder
        if port in (80, 8080, 8000, 8888):
            sock.send(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        elif port in (443, 8443):
            # HTTPS için düz bağlantıda banner bekle
            pass

        # Yanıtı oku (ilk 256 byte yeterli)
        banner = sock.recv(256).decode("utf-8", errors="ignore").strip()

        # Sadece ilk satırı al, temizle
        ilk_satir = banner.splitlines()[0] if banner else ""
        return ilk_satir[:120]

    except (socket.timeout, socket.error, OSError):
        return ""


def tek_port_tara(
    ip       : str,
    port     : int,
    timeout  : float,
    sonuc_q  : queue.Queue,
    banner_al: bool = True,
):
    """
    Tek bir porta TCP bağlantısı dener ve sonucu kuyruğa ekler.

    TCP 3-Way Handshake:
      SYN → SYN-ACK → ACK  (bağlantı kuruldu = port AÇIK)
      SYN → RST            (sunucu reddetti = port KAPALI)
      SYN → (cevap yok)    (timeout = filtrelenmiş)

    Args:
        ip       : Hedef IP adresi.
        port     : Taranacak port numarası.
        timeout  : Bağlantı zaman aşımı (saniye).
        sonuc_q  : Thread-safe sonuç kuyruğu.
        banner_al: True ise açık porttan banner oku.
    """
    sonuc = PortSonuc(
        port   = port,
        acik   = False,
        servis = SERVICE_DB.get(port, "?"),
    )

    try:
        # TCP socket oluştur (IPv4, güvenilir bağlantı)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Bağlanmayı dene (0 = başarılı = port AÇIK)
        kod = sock.connect_ex((ip, port))

        if kod == 0:
            sonuc.acik = True

            # Banner yakala
            if banner_al:
                sonuc.banner = banner_yakala(sock, port, timeout)

        sock.close()

    except socket.error as e:
        sonuc.hata = str(e)

    sonuc_q.put(sonuc)


def port_tara(
    hedef      : str,
    portlar    : list,
    timeout    : float = 1.0,
    max_thread : int   = 100,
    banner_al  : bool  = True,
) -> list:
    """
    Belirtilen portları paralel thread'lerle tarar.

    Args:
        hedef      : IP adresi veya hostname.
        portlar    : Taranacak port listesi.
        timeout    : Port başına zaman aşımı.
        max_thread : Eş zamanlı maksimum thread sayısı.
        banner_al  : Banner grabbing açık/kapalı.

    Returns:
        PortSonuc nesnelerinin listesi (sadece açık portlar, sıralı).
    """
    # Hostname → IP
    try:
        ip = socket.gethostbyname(hedef)
    except socket.gaierror:
        return []

    sonuc_q = queue.Queue()
    threadler = []

    for port in portlar:
        t = threading.Thread(
            target=tek_port_tara,
            args=(ip, port, timeout, sonuc_q, banner_al),
            daemon=True
        )
        threadler.append(t)

    # Gruplar halinde çalıştır
    for i in range(0, len(threadler), max_thread):
        grup = threadler[i: i + max_thread]
        for t in grup:
            t.start()
        for t in grup:
            t.join()

    # Sonuçları topla ve sırala
    sonuclar = []
    while not sonuc_q.empty():
        s = sonuc_q.get()
        if s.acik:
            sonuclar.append(s)

    return sorted(sonuclar, key=lambda x: x.port)
