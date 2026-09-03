# Patch Recon V2 — Tapo C200 V5

Extraire ce ZIP directement à la racine du projet :

```text
C:\Users\Arthur\PycharmProjects\etude-tapoc200-v5
```

Accepter le remplacement de :

```text
tapolab\cli.py
tapolab\rtsp.py
tapolab\onvif.py
```

Nouveaux fichiers :

```text
tapolab\wsdiscovery.py
tapolab\tlsprobe.py
tapolab\probe8800.py
tapolab\pcap_conversations.py
```

Aucune nouvelle dépendance Python.

## Test rapide

```powershell
python .\main.py --help
python .\main.py rtsp-describe
python .\main.py ws-discovery
python .\main.py tls
python .\main.py probe-8800
python .\main.py onvif-matrix
```

## Tout lancer en une commande

```powershell
python .\main.py recon-v2
```

Le résultat est archivé dans :

```text
evidence\runs\<timestamp>\recon-v2.json
```

## Reconstitution de conversations TCP à partir d'un PCAP existant

Exemple :

```powershell
python .\main.py conversations `
  .\evidence\runs\20260903T113248Z\capture.pcap
```

Le parseur extrait :

- conversation TCP ;
- port côté caméra ;
- nombre de paquets ;
- nombre d'octets applicatifs ;
- aperçu ASCII par direction ;
- aperçu hexadécimal.

## Ce que Recon V2 mesure

### RTSP

```text
OPTIONS /
DESCRIBE /stream1
DESCRIBE /stream2
```

Aucun credential n'est fourni.

### ONVIF

Méthodes non destructives uniquement :

```text
GetDeviceInformation
GetSystemDateAndTime
GetCapabilities
GetServices
GetProfiles
GetStreamUri        seulement si un ProfileToken est réellement retourné
PTZ.GetConfigurations
```

Le but est de comparer la position de la frontière d'authentification entre
handlers, pas de contourner cette authentification.

### WS-Discovery

Un Probe ONVIF standard est envoyé à :

```text
239.255.255.250:3702
```

Seules les réponses provenant de l'IP cible du scope sont conservées.

### 443/TLS

Handshake standard sans validation de confiance, uniquement pour relever :

```text
version TLS
cipher
SHA-256 du certificat
métadonnées du certificat
```

### TCP/8800

Connexion TCP puis attente sans envoyer aucun octet applicatif :

```text
connect
↓
wait
↓
server-first ?
```

C'est volontairement passif.
