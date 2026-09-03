# Patch v0.5

Extraire à la racine du projet et accepter les remplacements.

## Correction de `conversations`

Le run `20260903T113936Z` est un run Recon V2 et ne contient donc pas de
`capture.pcap`.

Désormais :

```powershell
python .\main.py conversations
```

sélectionne automatiquement le dernier run contenant réellement un PCAP.

Autres formes acceptées :

```powershell
python .\main.py conversations latest
python .\main.py conversations 20260903T113248Z
python .\main.py conversations .\evidence\runs\20260903T113248Z
python .\main.py conversations .\evidence\runs\20260903T113248Z\capture.pcap
```

Même comportement pour :

```powershell
python .\main.py analyze
```

## Recon + capture dans un seul run

PowerShell administrateur :

```powershell
python .\main.py recon-capture --seconds 15
```

Le programme démarre la capture RAW, exécute la Recon V2, puis génère dans le
même dossier :

```text
capture.pcap
capture-summary.json
recon-capture.json
tcp-conversations.json
manifest.json
```

## RTSP

Les headers `WWW-Authenticate` multiples sont maintenant conservés. La sortie
distingue donc correctement :

```text
Basic
Digest
```

au lieu d'écraser le premier par le second.

## ONVIF

La matrice utilise désormais le `XAddr` annoncé par la caméra
(`/onvif/service`) pour les services.

Méthodes supplémentaires, toutes en lecture seule :

```text
GetServiceCapabilities
GetScopes
GetHostname
GetNetworkInterfaces
GetDNS
GetNTP
```

Aucune méthode de modification n'est appelée.
