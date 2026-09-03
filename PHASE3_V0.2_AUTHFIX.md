# Phase 3 v0.2 — Auth fix

Extraire à la racine du projet et accepter les remplacements.

Fichiers remplacés :

```text
phase3lab/onvif_auth.py
phase3lab/cli.py
```

Nouveau :

```text
phase3lab/authdiag.py
```

## Pourquoi

### RTSP

Si `Basic` ET `Digest` retournent tous deux `401`, le couple username/password
n'est pas accepté par le serveur RTSP.

Vérifier dans l'application Tapo :

```text
Caméra
→ Paramètres
→ Paramètres avancés
→ Compte caméra
```

Ce compte est distinct du compte TP-Link/Tapo cloud.

### ONVIF

La v0.1 avait un bug : elle parcourait `UTCDateTime` puis `LocalDateTime` et
pouvait finir avec l'heure locale marquée comme UTC.

Exemple observé :

```text
RTSP Date       ≈ 12:12 GMT
ancienne WSSE   = 14:12 UTC
```

La v0.2 extrait explicitement `<UTCDateTime>`.

## Diagnostic

Après avoir vérifié/réinitialisé le Compte caméra :

```powershell
$env:TAPO_CAMERA_USER="..."
$env:TAPO_CAMERA_PASSWORD="..."

python .\phase3.py auth-diagnose
```

Interprétation :

```text
Basic 200
Digest 200
→ credentials RTSP confirmés

Basic 401
Digest 401
→ compte caméra / username / password à vérifier

RTSP OK + ONVIF NotAuthorized
→ investiguer WS-Security séparément
```

Ne lance pas `auth-diagnose` pendant une capture destinée à être partagée :
le diagnostic teste aussi Basic, donc les identifiants sont transportés en
Base64 sur le LAN pendant ce test.

Ensuite :

```powershell
python .\phase3.py rtsp-auth
python .\phase3.py onvif-auth
python .\phase3.py auth-capture --seconds 20
```
