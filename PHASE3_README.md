# Tapo C200 V5 — Phase 3 : sessions locales légitimes

Ce patch **n'écrase aucun fichier du lab actuel**.

Il ajoute :

```text
phase3.py
phase3lab/
```

et réutilise les composants `tapolab/` déjà présents.

## Objectifs

Passer de :

```text
LAN unauthenticated
```

à :

```text
LAN authenticated — compte caméra légitime
```

pour établir la baseline normale avant de chercher des écarts de logique.

Cette phase couvre :

- RTSP Digest authentifié ;
- lecture du SDP de `stream1` et `stream2` ;
- test Basic **uniquement sur demande explicite** ;
- ONVIF WS-Security `UsernameToken/PasswordDigest` ;
- profils média ;
- URI RTSP ;
- URI snapshot ;
- configurations encodeur vidéo/audio ;
- configurations et état PTZ en lecture seule ;
- capture PCAP corrélée.

Aucune commande de mouvement PTZ, reboot, reset, configuration ou écriture n'est envoyée.

---

## 1. Remettre la caméra sur Internet

Après l'expérience `CAMERA_WAN_OFF_CONFIRMED`, supprime/désactive la pause Bbox.

Le live distant 4G/5G doit revenir après reconnexion cloud.

---

## 2. Compte caméra

RTSP/ONVIF utilisent le **compte caméra local** créé dans l'application Tapo,
distinct du TP-Link ID/cloud.

Ne mets pas ces identifiants dans le repo.

Dans le terminal PowerShell courant :

```powershell
$env:TAPO_CAMERA_USER="MON_COMPTE_CAMERA"
$env:TAPO_CAMERA_PASSWORD="MON_MOT_DE_PASSE_CAMERA"
```

Ces variables disparaissent à la fermeture du terminal.

---

## 3. Doctor

```powershell
python .\phase3.py doctor
```

La sortie ne montre jamais le mot de passe.

---

## 4. RTSP Digest

```powershell
python .\phase3.py rtsp-auth
```

Pour chaque flux :

```text
DESCRIBE
  ↓
401 Basic + Digest
  ↓
Digest avec le compte caméra
  ↓
200 ?
  ↓
SDP
  ├── media
  ├── codecs RTP
  ├── fmtp
  └── control URI
```

### Tester Basic

Seulement après avoir validé Digest :

```powershell
python .\phase3.py rtsp-auth --also-basic
```

**Important :** Basic transporte `username:password` en Base64 sur RTSP non
chiffré. Ne lance pas cette commande pendant une capture que tu comptes partager.

Le JSON du lab ne stocke jamais l'en-tête Authorization.

---

## 5. ONVIF authentifié

```powershell
python .\phase3.py onvif-auth
```

Le lab utilise :

```text
WS-Security UsernameToken
PasswordDigest = Base64(SHA1(nonce + Created + password))
```

et génère un nouveau nonce par requête.

Méthodes en lecture seule :

```text
GetDeviceInformation
GetProfiles
GetVideoEncoderConfigurations
GetAudioEncoderConfigurations
PTZ.GetConfigurations
GetStreamUri
GetSnapshotUri
PTZ.GetStatus
```

---

## 6. Run authentifié + capture

PowerShell administrateur :

```powershell
python .\phase3.py auth-capture --seconds 20
```

Cette commande **n'utilise jamais RTSP Basic**.

Elle produit :

```text
evidence\runs\<timestamp>\
├── capture.pcap
├── authenticated-recon.json
├── capture-summary.json
├── tcp-conversations.json
└── manifest.json
```

Le mot de passe n'est écrit dans aucun JSON.

---

## Pourquoi cette phase est importante

Avant de tester des erreurs d'authentification, il faut connaître le comportement
normal :

```text
unauthenticated request
        ↓
challenge/refus

legitimate authenticated request
        ↓
expected media/config metadata
```

On pourra ensuite comparer handler par handler sans confondre comportement
normal et anomalie.
