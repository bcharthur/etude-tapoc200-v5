# S1 link-status → onboarding predicate slice — v1.0.17

## Objective

Recover the exact branch predicate(s) inside the physical Wi-Fi link-status handler that gate entry into onboarding/re-onboarding. No RF injection is performed.

## Root function

- `onboarding_phy_link_status_change_handle` @ `0x005366a0`, size `216`
- recovered direct caller sites: `2`

## Static bridge status

- direct link-handler → onboarding-start edge: `True`

## Gate slice: `onboarding_phy_link_status_change_handle` → `wlan_manager_onboarding_start`

Call site: `0x0053673c`

### Preceding branches

- `0x005366c4: beq a0,s0,53675c <onboarding_phy_link_status_change_handle+0xbc> -> 0x0053675c`
- `0x005366cc: bnez a0,536768 <onboarding_phy_link_status_change_handle+0xc8> -> 0x00536768`
- `0x00536720: beq v0,s0,536738 <onboarding_phy_link_status_change_handle+0x98> -> 0x00536738`
- `0x0053672c: bne v0,s0,53674c <onboarding_phy_link_status_change_handle+0xac> -> 0x0053674c`

### Nearby strings

- none recovered

### Instruction slice

```asm
  5366f4:	27a5001c 	addiu	a1,sp,28
  5366f8:	00002025 	move	a0,zero
  5366fc:	0411cf4a 	bal	52a428 <wlan_manager_ap_get_status>
  536700:	afa20018 	sw	v0,24(sp)
  536704:	8fbc0010 	lw	gp,16(sp)
  536708:	00002025 	move	a0,zero
  53670c:	8f9989dc 	lw	t9,-30244(gp)
  536710:	0411d446 	bal	52b82c <wlan_manager_monitor_get_status>
  536714:	27a50018 	addiu	a1,sp,24
  536718:	8fa2001c 	lw	v0,28(sp)
  53671c:	8fbc0010 	lw	gp,16(sp)
  536720:	10500005 	beq	v0,s0,536738 <onboarding_phy_link_status_change_handle+0x98>
  536724:	00002025 	move	a0,zero
  536728:	8fa20018 	lw	v0,24(sp)
  53672c:	14500007 	bne	v0,s0,53674c <onboarding_phy_link_status_change_handle+0xac>
  536730:	8f828838 	lw	v0,-30664(gp)
  536734:	24040004 	li	a0,4
  536738:	8f9989e0 	lw	t9,-30240(gp)
  53673c:	0411db6d 	bal	52d4f4 <wlan_manager_onboarding_start>
  536740:	00000000 	nop
  536744:	8fbc0010 	lw	gp,16(sp)
  536748:	8f828838 	lw	v0,-30664(gp)
  53674c:	8c42e964 	lw	v0,-5788(v0)
  536750:	10400005 	beqz	v0,536768 <onboarding_phy_link_status_change_handle+0xc8>
  536754:	8fbf0024 	lw	ra,36(sp)
  536758:	8f998a0c 	lw	t9,-30196(gp)
  53675c:	0320f809 	jalr	t9
```

## Gate slice: `onboarding_phy_link_status_change_handle` → `wlan_manager_ap_get_status`

Call site: `0x005366fc`

### Preceding branches

- `0x005366c4: beq a0,s0,53675c <onboarding_phy_link_status_change_handle+0xbc> -> 0x0053675c`
- `0x005366cc: bnez a0,536768 <onboarding_phy_link_status_change_handle+0xc8> -> 0x00536768`

### Nearby strings

- none recovered

### Instruction slice

```asm
  5366b4:	afb00020 	sw	s0,32(sp)
  5366b8:	afbc0010 	sw	gp,16(sp)
  5366bc:	24100001 	li	s0,1
  5366c0:	afbf0024 	sw	ra,36(sp)
  5366c4:	10900025 	beq	a0,s0,53675c <onboarding_phy_link_status_change_handle+0xbc>
  5366c8:	8f998964 	lw	t9,-30364(gp)
  5366cc:	14800026 	bnez	a0,536768 <onboarding_phy_link_status_change_handle+0xc8>
  5366d0:	8fbf0024 	lw	ra,36(sp)
  5366d4:	8f998a00 	lw	t9,-30208(gp)
  5366d8:	0411ffba 	bal	5365c4 <onboarding_ctx_init>
  5366dc:	00000000 	nop
  5366e0:	8fbc0010 	lw	gp,16(sp)
  5366e4:	24020008 	li	v0,8
  5366e8:	afa2001c 	sw	v0,28(sp)
  5366ec:	8f9988bc 	lw	t9,-30532(gp)
  5366f0:	24020005 	li	v0,5
  5366f4:	27a5001c 	addiu	a1,sp,28
  5366f8:	00002025 	move	a0,zero
  5366fc:	0411cf4a 	bal	52a428 <wlan_manager_ap_get_status>
  536700:	afa20018 	sw	v0,24(sp)
  536704:	8fbc0010 	lw	gp,16(sp)
  536708:	00002025 	move	a0,zero
  53670c:	8f9989dc 	lw	t9,-30244(gp)
  536710:	0411d446 	bal	52b82c <wlan_manager_monitor_get_status>
  536714:	27a50018 	addiu	a1,sp,24
  536718:	8fa2001c 	lw	v0,28(sp)
  53671c:	8fbc0010 	lw	gp,16(sp)
```

## Gate slice: `onboarding_phy_link_status_change_handle` → `wlan_manager_monitor_get_status`

Call site: `0x00536710`

### Preceding branches

- `0x005366c4: beq a0,s0,53675c <onboarding_phy_link_status_change_handle+0xbc> -> 0x0053675c`
- `0x005366cc: bnez a0,536768 <onboarding_phy_link_status_change_handle+0xc8> -> 0x00536768`

### Nearby strings

- none recovered

### Instruction slice

```asm
  5366c8:	8f998964 	lw	t9,-30364(gp)
  5366cc:	14800026 	bnez	a0,536768 <onboarding_phy_link_status_change_handle+0xc8>
  5366d0:	8fbf0024 	lw	ra,36(sp)
  5366d4:	8f998a00 	lw	t9,-30208(gp)
  5366d8:	0411ffba 	bal	5365c4 <onboarding_ctx_init>
  5366dc:	00000000 	nop
  5366e0:	8fbc0010 	lw	gp,16(sp)
  5366e4:	24020008 	li	v0,8
  5366e8:	afa2001c 	sw	v0,28(sp)
  5366ec:	8f9988bc 	lw	t9,-30532(gp)
  5366f0:	24020005 	li	v0,5
  5366f4:	27a5001c 	addiu	a1,sp,28
  5366f8:	00002025 	move	a0,zero
  5366fc:	0411cf4a 	bal	52a428 <wlan_manager_ap_get_status>
  536700:	afa20018 	sw	v0,24(sp)
  536704:	8fbc0010 	lw	gp,16(sp)
  536708:	00002025 	move	a0,zero
  53670c:	8f9989dc 	lw	t9,-30244(gp)
  536710:	0411d446 	bal	52b82c <wlan_manager_monitor_get_status>
  536714:	27a50018 	addiu	a1,sp,24
  536718:	8fa2001c 	lw	v0,28(sp)
  53671c:	8fbc0010 	lw	gp,16(sp)
  536720:	10500005 	beq	v0,s0,536738 <onboarding_phy_link_status_change_handle+0x98>
  536724:	00002025 	move	a0,zero
  536728:	8fa20018 	lw	v0,24(sp)
  53672c:	14500007 	bne	v0,s0,53674c <onboarding_phy_link_status_change_handle+0xac>
  536730:	8f828838 	lw	v0,-30664(gp)
```

## Gate slice: `onboarding_phy_link_status_change_handle` → `onboarding_ctx_init`

Call site: `0x005366d8`

### Preceding branches

- `0x005366c4: beq a0,s0,53675c <onboarding_phy_link_status_change_handle+0xbc> -> 0x0053675c`
- `0x005366cc: bnez a0,536768 <onboarding_phy_link_status_change_handle+0xc8> -> 0x00536768`

### Nearby strings

- none recovered

### Instruction slice

```asm
  5366a0:	3c1c0029 	lui	gp,0x29
  5366a4:	279cd6c0 	addiu	gp,gp,-10560
  5366a8:	0399e021 	addu	gp,gp,t9
  5366ac:	27bdffd8 	addiu	sp,sp,-40
  5366b0:	3084ffff 	andi	a0,a0,0xffff
  5366b4:	afb00020 	sw	s0,32(sp)
  5366b8:	afbc0010 	sw	gp,16(sp)
  5366bc:	24100001 	li	s0,1
  5366c0:	afbf0024 	sw	ra,36(sp)
  5366c4:	10900025 	beq	a0,s0,53675c <onboarding_phy_link_status_change_handle+0xbc>
  5366c8:	8f998964 	lw	t9,-30364(gp)
  5366cc:	14800026 	bnez	a0,536768 <onboarding_phy_link_status_change_handle+0xc8>
  5366d0:	8fbf0024 	lw	ra,36(sp)
  5366d4:	8f998a00 	lw	t9,-30208(gp)
  5366d8:	0411ffba 	bal	5365c4 <onboarding_ctx_init>
  5366dc:	00000000 	nop
  5366e0:	8fbc0010 	lw	gp,16(sp)
  5366e4:	24020008 	li	v0,8
  5366e8:	afa2001c 	sw	v0,28(sp)
  5366ec:	8f9988bc 	lw	t9,-30532(gp)
  5366f0:	24020005 	li	v0,5
  5366f4:	27a5001c 	addiu	a1,sp,28
  5366f8:	00002025 	move	a0,zero
```

## Interpretation discipline

CONFIRMÉ: a direct call edge is static control-flow evidence.

À TESTER: the exact runtime values/reason codes needed to choose that branch.

NON DÉMONTRÉ: RF-only factory reset. Re-onboarding/SoftAP and factory reset remain separate states until configuration erasure/unbinding is observed.
