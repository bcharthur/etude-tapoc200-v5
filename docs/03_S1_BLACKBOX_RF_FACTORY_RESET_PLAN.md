# S1 black-box RF plan — radio-only factory/provisioning pivot

## Objective

Start condition:

- camera is NORMAL, provisioned and bound to its normal Wi-Fi;
- attacker is within radio range only;
- attacker does not know the Wi-Fi PSK;
- attacker is not associated to the AP;
- attacker has no camera IP path, Tapo account or physical access.

Success condition:

- the camera enters a persistent factory/provisioning/unbound state because of radio traffic alone;
- ideally `Tapo_Cam_*` appears and the camera behaves as after factory reset;
- result is repeatable and causally distinguishable from an ordinary reboot or temporary Wi-Fi outage.

## What can actually reach the camera under S1?

While the camera is a Wi-Fi station, normal IP services are out of scope as an initial trigger. The reachable attack surface is primarily pre-association 802.11 handling:

1. management frames received by the station/driver/firmware (beacon, probe response, authentication, association response, deauthentication, disassociation and some action frames);
2. roaming/reconnect/security negotiation state machines influenced by observed AP advertisements and failures;
3. any vendor/P2P/WPS/DPP/provisioning listener active before association;
4. Wi-Fi chipset/driver parser bugs that process frames before the normal network stack.

## Why simple deauthentication is not enough

A standard deauthentication/disassociation frame can at most remove connectivity if accepted. By itself it does not mean factory reset. It becomes relevant only if the camera has unsafe recovery behavior such as:

`radio disconnect -> repeated reconnect failure -> recovery policy -> SoftAP/provisioning -> configuration loss`

Therefore the experiment must observe **state**, not merely ping loss or reboot.

## Highest-value hypotheses

### H1 — disconnect/reconnect fallback bug

A bounded sequence of legitimate-looking deauthentication/disassociation or authentication failure events may drive a recovery counter and eventually enable provisioning/backup Wi-Fi mode.

Why plausible: embedded cameras often have explicit Wi-Fi recovery/fallback state machines. The firmware/rootfs contains Wi-Fi operation tooling and multiple provisioning-related components. The exact trigger threshold is unknown.

### H2 — evil-twin/roaming failure state confusion

A spoofed advertisement for the configured SSID/BSSID, followed by controlled association/handshake failure, could lure the station away from the legitimate AP and exercise error paths that ordinary deauthentication does not reach.

The attacker still does not know the PSK; the value of the test is the state-machine failure itself, not completing the Wi-Fi handshake.

### H3 — pre-association management/action parser bug

Malformed but bounded management/action frames addressed to the camera may reach chipset/driver/P2P/WPS/DPP parsers before association. A memory-safety bug would more likely cause crash/reboot than factory reset, but a crash into an unsafe recovery state could become a pivot.

### H4 — vendor/secondary-radio provisioning surface

The rootfs contains references to several wireless components (`rtl8188*`, `wq9001*`, `esp32*`). Static analysis must determine whether any secondary-radio or vendor provisioning logic remains active during NORMAL state.

## Experiment order

### Phase A — passive baseline

Record without association:

- camera MAC/BSSID relationships;
- configured AP channel and RSN/PMF capabilities;
- camera reconnect timing after natural AP loss;
- whether the camera emits probe requests/P2P/action traffic in NORMAL state;
- whether `Tapo_Cam_*` ever appears during ordinary reconnects.

No claim is made from passive discovery alone.

### Phase B — bounded standard management events

Use one or a very small number of frames per trial against the owned camera. Separate trials for deauthentication, disassociation and selected standards-compliant failure/status cases. After each trial, observe for a fixed window and classify:

- no effect;
- temporary disconnect/reconnect;
- reboot;
- recovery/SoftAP;
- factory/unbound state.

Avoid flood-style testing because it destroys causal attribution.

### Phase C — recovery counter/state-machine tests

If a single event only reconnects, test a bounded number of repeated *cycles* rather than high-rate frames. The key variable is the camera's internal reconnect/recovery counter, not packet volume.

### Phase D — targeted parser corpus

Only after Phase A-C identify a reachable management/action family should malformed-frame testing be added. Keep the corpus small, mutate one field at a time, and preserve a control trial. A reboot is recorded separately from a factory/provisioning transition.

### Phase E — chain completion

If `Tapo_Cam_*` appears or the device becomes unbound:

1. confirm attacker never associated to the original protected WLAN;
2. join the camera's provisioning SoftAP;
3. reuse the already demonstrated TPAP `pake:[0]` MAC-derived bootstrap;
4. verify whether privileged configuration/third-account creation is still possible;
5. optionally reproduce the SETUP Streamd disclosure as a separate impact step.

This converts the existing SETUP findings into an end-to-end S1 chain only if the radio-only state pivot is demonstrated first.

## Evidence required for an S1 claim

Preserve at minimum:

- pre-test state showing NORMAL/bound firmware and no `Tapo_Cam_*` SoftAP;
- attacker interface in monitor/injection mode and explicitly not associated;
- exact frame class/count/timestamps used in the trial;
- independent state observation during/after the trial;
- appearance of provisioning/factory indicators;
- repeat trial from a clean NORMAL state;
- negative/control trial where no trigger is sent.

## Stop conditions

Do not interpret these as factory reset:

- a single missed ping;
- RTSP/ONVIF/HTTPS temporary outage;
- camera reboot with configuration intact;
- ordinary Wi-Fi reconnect;
- attacker's inability to hear the camera because of channel changes.
