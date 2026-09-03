# Phase 2 — Conclusions confirmées au 3 septembre 2026

## Cible

```text
Tapo C200 V5
IP  : 192.168.1.79
MAC : dc:62:79:8b:3a:da
```

## Surface LAN observée

```text
80/TCP    CLOSED (RST/ACK observé)
443/TCP   OPEN — TLS 1.3
554/TCP   OPEN — RTSP
2020/TCP  OPEN — ONVIF/SOAP
8800/TCP  OPEN — protocole client-first
3702/UDP  WS-Discovery
```

## RTSP sans authentification

`OPTIONS` :

```text
RTSP/1.0 200 OK
Public:
OPTIONS, DESCRIBE, SETUP, TEARDOWN,
PLAY, PAUSE, GET_PARAMETER, SET_PARAMETER
```

`DESCRIBE /stream1` et `/stream2` :

```text
401 Unauthorized
Basic realm="TP-Link IP-Camera"
Digest realm="TP-Link IP-Camera", nonce=...
```

Les nonces observés changent entre requêtes.

Le fait que Basic soit **annoncé** est confirmé ; son acceptation effective doit
être vérifiée avec le compte caméra légitime.

## WS-Discovery / ONVIF

La caméra répond à un Probe standard :

```text
Type    : NetworkVideoTransmitter
Name    : C200
Hardware: C200
Profile : Streaming
XAddr   : http://192.168.1.79:2020/onvif/device_service
```

EndpointReference observé :

```text
uuid:3fa1fe68-b915-4053-a3e1-dc62798b3ada
```

Le scope `location/Hong Kong` est une métadonnée ONVIF annoncée par le device ;
ce n'est pas une preuve de localisation physique ou de destination cloud.

### Frontière pré-auth observée

Accessibles sans credentials :

```text
GetSystemDateAndTime
GetCapabilities
GetServices
GetServiceCapabilities
```

Refusés avec `ter:NotAuthorized` :

```text
GetDeviceInformation
GetScopes
GetHostname
GetNetworkInterfaces
GetDNS
GetNTP
GetProfiles
PTZ.GetConfigurations
```

La frontière observée est cohérente : capacités générales accessibles,
informations/configurations concrètes protégées.

## TLS local / 443

Handshake confirmé :

```text
TLSv1.3
TLS_AES_128_GCM_SHA256
```

Certificat :

```text
CN     = TPRI-DEVICE
O      = TPRI
C      = US
Issuer = self
Serial = 01
Valid  = 2001-01-01 → 2070-12-31
SHA256 = 87468b62b3519267f92b79174052035549ea0eb216b1e735046a9bc7c52fa575
```

Avec un seul appareil on ne peut pas conclure que le certificat ou la clé
privée sont partagés entre plusieurs caméras.

## TCP/8800

Confirmé :

```text
TCP open
client-first
aucun banner
aucun octet serveur après ~2 s d'attente
connexion conservée
```

Le protocole applicatif n'est pas encore identifié sur cette V5.

---

# Expérience Camera WAN OFF

La Bbox a appliqué une pause Internet à la caméra uniquement.

Pendant la pause :

```text
PC LAN → 192.168.1.79     OK
Camera → WAN/cloud         bloqué
```

Validation fonctionnelle :

### Téléphone en 4G/5G

```text
Tapo → live
résultat : échec / « Appuyez pour actualiser »
```

Donc l'accès distant ne peut plus établir le flux lorsque le WAN de la caméra
est coupé.

### Téléphone replacé sur le même Wi-Fi

Sans rendre Internet à la caméra :

```text
Tapo → live
résultat : fonctionne
```

## Conclusion architecturale importante

Il existe donc un chemin de live local utilisable lorsque :

```text
caméra LAN = ON
caméra WAN/cloud = OFF
téléphone = même LAN
```

La caméra n'a pas besoin d'une connexion cloud active pour fournir le live
local à l'application déjà authentifiée.

Cela ne prouve pas que l'application téléphone ne contacte jamais le cloud :
le téléphone peut encore utiliser Internet pour certaines métadonnées ou
fonctions de contrôle. Ce qui est démontré est que **le chemin média/local
caméra reste opérationnel sans WAN côté caméra**.

## Comparaison des runs

Baseline caméra WAN ON :

```text
20260903T114518Z
238 paquets
2020: 184
554 : 27
443 : 19
8800: 7
3702: 1
```

Caméra WAN OFF confirmé :

```text
20260903T115940Z
238 paquets
2020: 184
554 : 27
443 : 20
8800: 6
3702: 1
```

La surface LAN et son comportement sont pratiquement invariants.

## Conclusion Phase 2

```text
                          C200 V5
                         /       \
                        /         \
                 LOCAL PATH      CLOUD PATH
                    ✅               ✅ normalement
                    │
                    │ WAN camera OFF
                    │
                 reste ✅             ❌
                    │
          ┌─────────┼──────────┐
          ▼         ▼          ▼
        RTSP      ONVIF     Tapo live local
         ✅         ✅           ✅

Téléphone distant 4G/5G → Tapo live : ❌
```

La phase suivante doit établir les sessions locales **légitimes authentifiées**
afin d'obtenir la baseline RTSP/ONVIF normale avant toute recherche de bypass.
