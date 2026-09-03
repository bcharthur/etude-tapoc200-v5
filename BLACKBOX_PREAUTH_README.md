# Black-box / Pre-auth — Tapo C200 V5

Ce patch est destiné au scénario **sans identifiants**.

Il n'utilise jamais :

```text
TAPO_CAMERA_USER
TAPO_CAMERA_PASSWORD
TP-Link ID
cloud token
```

## Important sur les scénarios

Le poste actuel est déjà associé au LAN `192.168.1.0/24`.

Donc ces tests représentent précisément :

```text
attaquant LAN sans credentials
```

et non encore le pur scénario RF :

```text
attaquant à portée Wi-Fi
sans PSK
sans IP connectivity
```

Pour le scénario RF pur, il faudra d'abord trouver un premier maillon donnant
une connectivité (provisioning, radio, reset chain, etc.). Les primitives
pré-auth LAN trouvées ici pourraient ensuite devenir le **deuxième maillon**.

## Commandes

### 1. RTSP — test de régression historique

```powershell
python .\blackbox.py rtsp-regression
```

La connexion TCP va toujours vers `192.168.1.79:554`.

Seule l'URI RTSP est modifiée :

```text
rtsp://192.168.1.79:554/stream1
rtsp://127.0.0.1:554/stream1
rtsp://localhost:554/stream1
```

et même chose pour `stream2`.

But :

```text
401 pour tous -> pas de bypass observé

200 + SDP uniquement pour localhost/127.0.0.1
-> candidat auth bypass / régression historique
```

Ce test est inspiré d'une faiblesse documentée sur une ancienne architecture
C200. Il ne présume PAS que la V5 est vulnérable.

### 2. TCP/8800 — challenge

```powershell
python .\blackbox.py 8800-challenge
```

Envoie seulement :

```text
POST /stream
aucun Authorization
Content-Length: 0
```

On veut connaître le challenge réellement renvoyé par la V5.

### 3. TCP/8800 — demande preview avant auth

```powershell
python .\blackbox.py 8800-preauth
```

Requête bornée, sans credentials.

Comportement sûr attendu :

```text
401 / refus
aucun média
```

À signaler :

```text
HTTP 200 avant auth
video/mp2t avant auth
device-stream-boundary + média avant auth
```

### 4. HTTPS/443 — discovery pré-auth

```powershell
python .\blackbox.py 443-discover
```

Essaie uniquement des messages de négociation/discovery pré-auth observés dans
des implémentations communautaires récentes.

Aucun login n'est complété.

On cherche des métadonnées de négociation telles que :

```text
pake
encrypt_type
user_hash_type
nonce
tls
port
```

### 5. Tout lancer

```powershell
python .\blackbox.py sweep
```

Résultat :

```text
evidence\runs\<timestamp>\
├── blackbox-preauth.json
└── manifest.json
```

## Ce que le patch ne fait PAS

```text
pas de brute-force
pas de password guessing
pas de replay d'identifiants
pas de CVE-2026-1871
pas de buffer overflow
pas de reboot
pas de factory reset
pas de fuzzing massif
```
