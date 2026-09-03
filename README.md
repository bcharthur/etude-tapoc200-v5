# Étude Tapo C200 V5 — Lab Python autonome

Cette version n'utilise **ni Wireshark, ni TShark, ni Npcap**.

Cible :

- IP : `192.168.1.79`
- MAC : `dc:62:79:8b:3a:da`
- scope : `192.168.1.0/24`

## Installation

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Dépendances Python :

- `rich`
- `psutil`

La capture elle-même utilise uniquement la bibliothèque standard Python :
`socket`, `struct`, `time`.

## Baseline

```powershell
python .\main.py identify
python .\main.py baseline
```

## Voir l'interface choisie pour atteindre la caméra

```powershell
python .\main.py interfaces
```

Le programme détermine automatiquement l'IPv4 locale correspondant à la route
vers `192.168.1.79`.

## Capture réseau 100 % intégrée

Ouvre **PowerShell ou PyCharm en administrateur**, puis :

```powershell
python .\main.py capture --seconds 90
```

Sous Windows, le moteur utilise :

```text
socket(AF_INET, SOCK_RAW, IPPROTO_IP)
       ↓
SIO_RCVALL
       ↓
filtre Python src/dst = 192.168.1.79
       ↓
écriture PCAP native
       ↓
analyse TCP/UDP Python
```

Le résultat contient :

```text
evidence/runs/<timestamp>/
├── capture.pcap
├── capture.json
├── capture-summary.json
└── manifest.json
```

`capture-summary.json` fournit automatiquement :

- nombre de paquets ;
- direction caméra → autre / autre → caméra ;
- TCP / UDP / ICMP ;
- pairs IP vus ;
- ports TCP vus côté caméra ;
- ports UDP vus côté caméra.

Le PCAP est au format standard `DLT_RAW` et peut être relu par le projet lui-même :

```powershell
python .\main.py analyze .\evidence\runs\<RUN>\capture.pcap
```

## Limitation importante d'un PC connecté normalement au Wi-Fi

Sur un réseau Wi-Fi commuté :

```text
Téléphone ───── AP ───── C200
               │
               └──── PC
```

le PC ne reçoit normalement pas les trames unicast :

```text
C200 ↔ Internet
Téléphone ↔ C200
```

qui ne lui sont pas destinées.

La capture RAW Python permet donc surtout d'analyser :

```text
PC ↔ C200
```

sans aucun logiciel externe.

Pour observer **toute** la caméra, y compris `C200 ↔ cloud`, la phase suivante du
lab consistera à faire passer la caméra par une passerelle/hotspot contrôlée par
le PC. Le moteur d'analyse PCAP restera exactement le même.

## Commandes

```powershell
python .\main.py identify
python .\main.py discover
python .\main.py interfaces
python .\main.py ports
python .\main.py rtsp
python .\main.py onvif
python .\main.py baseline
python .\main.py capture --seconds 90
python .\main.py analyze <capture.pcap>
```

## Ports baseline

```text
80/tcp
443/tcp
554/tcp
2020/tcp
8800/tcp
```

`8800/tcp` reste une signature historique à vérifier, pas une hypothèse imposée
à la C200 V5.

## Expérience immédiate

1. `python .\main.py identify`
2. `python .\main.py baseline`
3. ouvrir PowerShell en administrateur ;
4. `python .\main.py capture --seconds 60`
5. pendant cette capture, lancer `python .\main.py rtsp` dans un second terminal ;
6. analyser `capture-summary.json`.

Cela valide tout le pipeline Python avant de construire le mode passerelle.
