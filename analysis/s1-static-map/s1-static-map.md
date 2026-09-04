# S1 static map — black-box RF factory/provisioning pivot

## Scope

NORMAL/bound camera -> factory/provisioning state using only nearby radio frames; attacker is not associated, has no PSK, no IP reachability and no physical access.

Main: `analysis\c200v5-142\main-1.4.2`
SHA-256: `3d5d7d8a35fdad2766848c6de2edd8fcb1db6f1392013d2d9556cb192cdfab37`

## Why this matters

TPAP/RTSP/ONVIF/HTTPS findings are chain-completion surfaces after a state pivot; they are not by themselves an S1 trigger while the camera remains a normal Wi-Fi STA.

## Binary hits

### factory_reset_state (111)
- `off=0xc2ab` `vaddr=0x0040c2ab` — `wlan_manager_reboot_thread`
- `off=0xc2f5` `vaddr=0x0040c2f5` — `wlan_manager_reboot`
- `off=0xfff1` `vaddr=0x0040fff1` — `IMP_System_UnBind`
- `off=0x2d7258` `vaddr=0x006d7258` — `/tmp/recovery_mode`
- `off=0x2d726c` `vaddr=0x006d726c` — `[DS]IN RECOVERY MODE DONOT WRITE CONFIG !!!`
- `off=0x2d7906` `vaddr=0x006d7906` — `        config recover         recover module config`
- `off=0x2d7b39` `vaddr=0x006d7b39` — `        ubus call ds config.recover '["video","OSD"]'`
- `off=0x2d80f0` `vaddr=0x006d80f0` — `config.recover`
- `off=0x2d8198` `vaddr=0x006d8198` — `ds_config_recover`
- `off=0x2e1714` `vaddr=0x006e1714` — `UnBind FrameSource channel%d and OSD failed`
- `off=0x2e1744` `vaddr=0x006e1744` — `UnBind OSD%d and Encoder failed`
- `off=0x2e7dd4` `vaddr=0x006e7dd4` — `timing_reboot`
- `off=0x2e85b0` `vaddr=0x006e85b0` — `config_recovery`
- `off=0x2e8d54` `vaddr=0x006e8d54` — `reboot`
- `off=0x2ec244` `vaddr=0x006ec244` — `[COVER]Recover handle ERROR.`
- `off=0x2ede28` `vaddr=0x006ede28` — `[DR]Recover handle ERROR.`
- `off=0x2ee53c` `vaddr=0x006ee53c` — `[IMAGE]Recover handle ERROR.`
- `off=0x2f1484` `vaddr=0x006f1484` — `[HSR]Recover handle ERROR.`
- `off=0x2f88a4` `vaddr=0x006f88a4` — `plan to reboot`
- `off=0x2f88b4` `vaddr=0x006f88b4` — `iw_add_worker _ptz_system_reboot_delay failed`
- `off=0x2f88e4` `vaddr=0x006f88e4` — `iw_add_worker _ptz_system_reboot_delay success`
- `off=0x2f8924` `vaddr=0x006f8924` — `reboot -f`
- `off=0x2f8930` `vaddr=0x006f8930` — `reboot -f fail!`
- `off=0x2f89e8` `vaddr=0x006f89e8` — `reboot time is %s`
- `off=0x2f8b14` `vaddr=0x006f8b14` — `plan_calculate_reboot_time`
- `off=0x2f8b98` `vaddr=0x006f8b98` — `_ptz_system_reboot_delay`
- `off=0x2f8bb4` `vaddr=0x006f8bb4` — `ptz_system_reboot_delay`
- `off=0x2fd0fc` `vaddr=0x006fd0fc` — `recover_priority_handle`
- `off=0x2fd7b4` `vaddr=0x006fd7b4` — `[WLAN]WLAN driver reboot......`
- `off=0x2fda80` `vaddr=0x006fda80` — `wlan recovery delay %d.`
- `off=0x2fda98` `vaddr=0x006fda98` — `wlan recovery delay param(%d) error, use default max 15s`
- `off=0x2fdad4` `vaddr=0x006fdad4` — `wlan reboot start.`
- `off=0x2fdae8` `vaddr=0x006fdae8` — `wlan reboot done.`
- `off=0x2fdb80` `vaddr=0x006fdb80` — `wlan_manager_reboot`
- `off=0x2fdb94` `vaddr=0x006fdb94` — `wlan_manager_reboot_thread`
- `off=0x2ffb31` `vaddr=0x006ffb31` — ` !!!Got a noscan err ,count %d,ALLOW recover %d`
- `off=0x304db0` `vaddr=0x00704db0` — `sync_info_to_unbind_hub`
- `off=0x30bffc` `vaddr=0x0070bffc` — `[UPGRADE]sd firmware upgrade success, sleep... Please Reboot!`
- `off=0x30c03c` `vaddr=0x0070c03c` — `[UPGRADE]sd firmware upgrade fail, sleep... Please Reboot!`
- `off=0x313d50` `vaddr=0x00713d50` — `factory_default`

### provisioning_softap (250)
- `off=0xc152` `vaddr=0x0040c152` — `is_onboarding_finished`
- `off=0xc195` `vaddr=0x0040c195` — `onboarding_restart`
- `off=0xc1a8` `vaddr=0x0040c1a8` — `tss_onboarding_role`
- `off=0xc1f5` `vaddr=0x0040c1f5` — `onboarding_force_cfg_audio`
- `off=0xc274` `vaddr=0x0040c274` — `onboarding_set_start_flag`
- `off=0xc2d8` `vaddr=0x0040c2d8` — `onboarding_execute_shell_cmd`
- `off=0xc424` `vaddr=0x0040c424` — `wlan_manager_onboarding_start`
- `off=0xc4c1` `vaddr=0x0040c4c1` — `onboarding_ctx_init`
- `off=0xc4e8` `vaddr=0x0040c4e8` — `is_onboarding_ds_module_start`
- `off=0xc506` `vaddr=0x0040c506` — `onboarding_module_start`
- `off=0xc51e` `vaddr=0x0040c51e` — `is_onboarding_started`
- `off=0xc6b6` `vaddr=0x0040c6b6` — `is_reonboarding`
- `off=0xc6d9` `vaddr=0x0040c6d9` — `set_onboarding_finished`
- `off=0xc6f1` `vaddr=0x0040c6f1` — `get_cur_onboarding_mode`
- `off=0xc740` `vaddr=0x0040c740` — `set_exit_softap_fast_flag`
- `off=0xc7e1` `vaddr=0x0040c7e1` — `ffs_onboarding_stop`
- `off=0xc88f` `vaddr=0x0040c88f` — `onboarding_phy_link_status_change_handle`
- `off=0xc954` `vaddr=0x0040c954` — `stop_exit_softap`
- `off=0xc979` `vaddr=0x0040c979` — `g_onboarding_mode`
- `off=0xc999` `vaddr=0x0040c999` — `ffs_onboarding_start`
- `off=0xca07` `vaddr=0x0040ca07` — `onboarding_cmd_init`
- `off=0xcda5` `vaddr=0x0040cda5` — `ffsSetWifiProvisioneeState`
- `off=0xcdf2` `vaddr=0x0040cdf2` — `ffsWifiProvisioneeCanProceed`
- `off=0xce0f` `vaddr=0x0040ce0f` — `ffsGetWifiProvisioneeState`
- `off=0xce2a` `vaddr=0x0040ce2a` — `ffsWifiProvisioneeStateIsTerminal`
- `off=0xce4c` `vaddr=0x0040ce4c` — `ffsGetWifiProvisioneeStateString`
- `off=0xcea1` `vaddr=0x0040cea1` — `ffsDssStartProvisioningSession`
- `off=0xcecd` `vaddr=0x0040cecd` — `ffsConvertDssWifiProvisioneeStateToApi`
- `off=0xcf2c` `vaddr=0x0040cf2c` — `ffsWifiProvisioneeCanPostWifiScanData`
- `off=0xcf69` `vaddr=0x0040cf69` — `ffsWifiProvisioneeCanGetWifiCredentials`
- `off=0xcfe1` `vaddr=0x0040cfe1` — `ffsSetWifiProvisioneeCanProceed`
- `off=0xd328` `vaddr=0x0040d328` — `ffsDssGetWifiProvisioneeStateString`
- `off=0xde9c` `vaddr=0x0040de9c` — `ffsDssDeserializeStartProvisioningSessionResponse`
- `off=0xdee7` `vaddr=0x0040dee7` — `ffsDssSerializeStartProvisioningSessionRequest`
- `off=0xe051` `vaddr=0x0040e051` — `ffsWifiProvisioneeTask`
- `off=0xe787` `vaddr=0x0040e787` — `ffsDssParseWifiProvisioneeState`
- `off=0x10559` `vaddr=0x00410559` — `build_old_tss_provision_data`
- `off=0xa6a59` `vaddr=0x004a6a59` — ` dpP`
- `off=0x127f61` `vaddr=0x00527f61` — `(dpp`
- `off=0x2cbe06` `vaddr=0x006cbe06` — `[1;36m******sound onboarding stopped, sample_rate before: %d, after: %d`

### wifi_events (65)
- `off=0xaee5` `vaddr=0x0040aee5` — `mbedtls_ssl_handshake`
- `off=0xb79c` `vaddr=0x0040b79c` — `mbedtls_ssl_conf_handshake_timeout`
- `off=0xbd2c` `vaddr=0x0040bd2c` — `wlan_sta_disconnect`
- `off=0xc5e1` `vaddr=0x0040c5e1` — `wlan_manager_sta_disconnect`
- `off=0xc629` `vaddr=0x0040c629` — `disconnect_WiFi_ex`
- `off=0xc845` `vaddr=0x0040c845` — `wlan_manual_reconnect`
- `off=0xca1b` `vaddr=0x0040ca1b` — `wlan_manager_init_reconnect_ctx`
- `off=0xcfaa` `vaddr=0x0040cfaa` — `ffsDisconnectFromSetupNetwork`
- `off=0xdb6f` `vaddr=0x0040db6f` — `ffsRaspbianWifiManagerDisconnect`
- `off=0xe8d5` `vaddr=0x0040e8d5` — `ffsWifiManagerDisconnect`
- `off=0xeaea` `vaddr=0x0040eaea` — `http_web_disconnect`
- `off=0x2e5fc0` `vaddr=0x006e5fc0` — `ssl handshake ret(%d)`
- `off=0x2fde44` `vaddr=0x006fde44` — `[ONBOARDING]TSS reconnect is failed`
- `off=0x2fe90c` `vaddr=0x006fe90c` — `[WLAN_BACKUP] wlan disconnected re selecting`
- `off=0x2feda0` `vaddr=0x006feda0` — `[WLAN]WLAN STA DISCONNECTED.`
- `off=0x2fef98` `vaddr=0x006fef98` — `reason_code`
- `off=0x2fefa4` `vaddr=0x006fefa4` — `reason_code=%d %s`
- `off=0x2ffef8` `vaddr=0x006ffef8` — `/tmp/scan_results`
- `off=0x305f7c` `vaddr=0x00705f7c` — `link_down_inner`
- `off=0x308ef8` `vaddr=0x00708ef8` — `%s[%d] Alloc scan result list failed`
- `off=0x308f3c` `vaddr=0x00708f3c` — `%s[%d] Local auth failed, %02x:%02x:%02x:%02x:%02x:%02x`
- `off=0x3092ac` `vaddr=0x007092ac` — `%s[%d] Auth failed, %02x:%02x:%02x:%02x:%02x:%02x`
- `off=0x3093e8` `vaddr=0x007093e8` — `tssd_reconnect_timer_handler`
- `off=0x309978` `vaddr=0x00709978` — `%s[%d] conf is same, no need to reconnect`
- `off=0x30a0e0` `vaddr=0x0070a0e0` — `tss_get_scan_result`
- `off=0x31055c` `vaddr=0x0071055c` — `Failed to connect to a user network, reconnecting to setup network`
- `off=0x310b08` `vaddr=0x00710b08` — `Start disconnecting from setup network`
- `off=0x310b44` `vaddr=0x00710b44` — `Disconnected from setup network`
- `off=0x310be8` `vaddr=0x00710be8` — `ffsDisconnectFromSetupNetwork`
- `off=0x311148` `vaddr=0x00711148` — `DISCONNECTED`
- `off=0x312614` `vaddr=0x00712614` — `No scan results`
- `off=0x3138fc` `vaddr=0x007138fc` — `Failed to wait on network disconnection semaphore`
- `off=0x31a32c` `vaddr=0x0071a32c` — `[LocalCtrl]ssl handshake fail!`
- `off=0x31a488` `vaddr=0x0071a488` — `localctrl_ssl_handshake_start`
- `off=0x321790` `vaddr=0x00721790` — `[ONVIF]Auth failed`
- `off=0x32e4b8` `vaddr=0x0072e4b8` — `[HTTPD]tpssl_svr_handshake err ret: -0x%x, free context.`
- `off=0x330888` `vaddr=0x00730888` — `stc_ip_link_down`
- `off=0x330be8` `vaddr=0x00730be8` — `LINK_DOWN`
- `off=0x330c34` `vaddr=0x00730c34` — `[NIFC]link down timeout!`
- `off=0x331334` `vaddr=0x00731334` — `link_down_timer_handle`

### wifi_stack (88)
- `off=0xa062` `vaddr=0x0040a062` — `esp32_driver_flag`
- `off=0x2d81cc` `vaddr=0x006d81cc` — `system nsd tdpd tdpc tmpd mactool wirelesstool protocol factory_status network dhcpc telemetry debug_tools dhcps cloud_iot wlan upgrade osd(avts) avts remote_debugger ffs tssd hub_`
- `off=0x2e2578` `vaddr=0x006e2578` — `insmod /lib/modules/%s/esp32.ko `
- `off=0x2e259c` `vaddr=0x006e259c` — `rmmod esp32 `
- `off=0x2e7f40` `vaddr=0x006e7f40` — `wireless_hotspot`
- `off=0x2fd9e8` `vaddr=0x006fd9e8` — `get_wireless_info`
- `off=0x2fecbc` `vaddr=0x006fecbc` — `rtl8188fu`
- `off=0x2fecf4` `vaddr=0x006fecf4` — `wq9001`
- `off=0x2fecfc` `vaddr=0x006fecfc` — `[wlan] use wq9001 adapter`
- `off=0x2feddc` `vaddr=0x006feddc` — `nl80211`
- `off=0x2fede4` `vaddr=0x006fede4` — `wpa_supplicant -B -D%s -i%s -P%s -C%s -b%s`
- `off=0x2fee10` `vaddr=0x006fee10` — `killall wpa_supplicant`
- `off=0x2fee3c` `vaddr=0x006fee3c` — `[WLAN]sleep 1s for waiting kill wpa_supplicant`
- `off=0x2ff23c` `vaddr=0x006ff23c` — `[WLAN]sleep 1s for waiting kill hostapd`
- `off=0x2ff264` `vaddr=0x006ff264` — `hostapd -B -P %s %s`
- `off=0x2ff280` `vaddr=0x006ff280` — `busybox killall hostapd`
- `off=0x2ff298` `vaddr=0x006ff298` — `/var/run/hostapd`
- `off=0x2ff2b8` `vaddr=0x006ff2b8` — `/tmp/hostapd_pid`
- `off=0x2ff568` `vaddr=0x006ff568` — `/tmp/hostapd.accept`
- `off=0x2ff57c` `vaddr=0x006ff57c` — `/tmp/hostapd.deny`
- `off=0x2ff5b4` `vaddr=0x006ff5b4` — `wlan_hostapd_start`
- `off=0x2ff5d8` `vaddr=0x006ff5d8` — `/proc/net/rtl8188fu/wlan0/gpio_set_output_value`
- `off=0x2ff608` `vaddr=0x006ff608` — `/proc/net/rtl8188fu/wlan0/gpio_set_direction`
- `off=0x2ff714` `vaddr=0x006ff714` — `/proc/net/rtl8188fu/wlan1/mac_addr`
- `off=0x2ff87c` `vaddr=0x006ff87c` — `cat /proc/net/rtl8188fu/wlan0/rx_signal | grep rssi`
- `off=0x2ff934` `vaddr=0x006ff934` — `/proc/net/rtl8188fu/driver_status`
- `off=0x2ff960` `vaddr=0x006ff960` — `/etc/default/hostapd_default.conf`
- `off=0x2ff984` `vaddr=0x006ff984` — `/tmp/hostapd.conf`
- `off=0x2ff998` `vaddr=0x006ff998` — `/etc/default/hostapd.accept`
- `off=0x2ff9b4` `vaddr=0x006ff9b4` — `/etc/default/hostapd.deny`
- `off=0x2ff9d8` `vaddr=0x006ff9d8` — `/proc/net/rtl8188fu/wlan0/detect_country`
- `off=0x2ffa38` `vaddr=0x006ffa38` — `/proc/net/rtl8188fu/wlan0/best_channel`
- `off=0x2ffab0` `vaddr=0x006ffab0` — `/proc/net/rtl8188fu/wlan0/survey_info`
- `off=0x2ffb94` `vaddr=0x006ffb94` — `cat /proc/net/rtl8188fu/wlan0/trx_info | awk 'NR==20 {print $6}'`
- `off=0x2ffc98` `vaddr=0x006ffc98` — `echo 0 > /proc/net/rtl8188fu/wlan0/sreset`
- `off=0x2ffce0` `vaddr=0x006ffce0` — `/var/run/wpa_supplicant`
- `off=0x30012c` `vaddr=0x0070012c` — `WQ9001_power_tab.dat`
- `off=0x300234` `vaddr=0x00700234` — `wq9001_ap_hostapd_conf`
- `off=0x304464` `vaddr=0x00704464` — `wireless`
- `off=0x309b74` `vaddr=0x00709b74` — `cap_wireless_freq`

### physical_reset_inputs (90)
- `off=0x2d9b38` `vaddr=0x006d9b38` — `[CAMERA]gpio%d is inited.`
- `off=0x2d9b54` `vaddr=0x006d9b54` — `/sys/class/gpio/export`
- `off=0x2d9b6c` `vaddr=0x006d9b6c` — `[CAMERA]camera_init_gpio_device failed.`
- `off=0x2d9bb0` `vaddr=0x006d9bb0` — `[CAMERA]camera_init_gpio_device set %d output failed.`
- `off=0x2d9be8` `vaddr=0x006d9be8` — `[CAMERA]camera_init_gpio_device set output failed.`
- `off=0x2d9c1c` `vaddr=0x006d9c1c` — `/sys/class/gpio/unexport`
- `off=0x2d9c38` `vaddr=0x006d9c38` — `[CAMERA]camera_uninit_gpio_device failed.`
- `off=0x2d9c84` `vaddr=0x006d9c84` — `[CAMERA]===================== ir_led_gpio_port %d.`
- `off=0x2d9cb8` `vaddr=0x006d9cb8` — `[CAMERA]camera_uninit_gpio :%d failed.`
- `off=0x2d9ce0` `vaddr=0x006d9ce0` — `[CAMERA]===================== ir_cut_double_gpio_ports.gpios[0] %d.`
- `off=0x2d9d24` `vaddr=0x006d9d24` — `[CAMERA]===================== ir_cut_double_gpio_ports.gpios[1] %d.`
- `off=0x2d9d68` `vaddr=0x006d9d68` — `/sys/class/gpio/gpio%d/value`
- `off=0x2d9d88` `vaddr=0x006d9d88` — `[CAMERA]set gpio value faied.`
- `off=0x2d9de0` `vaddr=0x006d9de0` — `/image_profile/ir_gpio_attr`
- `off=0x2d9dfc` `vaddr=0x006d9dfc` — `[CAMERA]ds read IR_GPIO_ATTR_S failed.`
- `off=0x2d9ec0` `vaddr=0x006d9ec0` — `camera_set_gpio_output_value`
- `off=0x2d9ee0` `vaddr=0x006d9ee0` — `camera_init_gpio`
- `off=0x2d9ef4` `vaddr=0x006d9ef4` — `camera_uninit_gpio_out_device`
- `off=0x2d9f14` `vaddr=0x006d9f14` — `camera_init_gpio_out_device`
- `off=0x2decfc` `vaddr=0x006decfc` — `[CAMERA]camera_init_gpio :%d failed.`
- `off=0x2dfac4` `vaddr=0x006dfac4` — `gpio_camera_image_wl_on`
- `off=0x2dfaf0` `vaddr=0x006dfaf0` — `gpio_camera_image_wl_off`
- `off=0x2e238c` `vaddr=0x006e238c` — `/gpio/gpio_cfg`
- `off=0x2e887c` `vaddr=0x006e887c` — `audio_speaker_enable_gpio`
- `off=0x2e8898` `vaddr=0x006e8898` — `ext_speaker_enable_gpio`
- `off=0x2e88cc` `vaddr=0x006e88cc` — `wifi_enable_gpio_active_low`
- `off=0x2e88e8` `vaddr=0x006e88e8` — `boot_led_gpio`
- `off=0x2e88f8` `vaddr=0x006e88f8` — `led_gpio_active_low`
- `off=0x2e890c` `vaddr=0x006e890c` — `red_led_gpio`
- `off=0x2e891c` `vaddr=0x006e891c` — `green_led_gpio`
- `off=0x2e892c` `vaddr=0x006e892c` — `blue_led_gpio`
- `off=0x2e893c` `vaddr=0x006e893c` — `reset_gpio`
- `off=0x2e8948` `vaddr=0x006e8948` — `white_led_gpio`
- `off=0x2e8958` `vaddr=0x006e8958` — `reset_gpio_press`
- `off=0x2e896c` `vaddr=0x006e896c` — `lens_mask_gpio`
- `off=0x2e897c` `vaddr=0x006e897c` — `lens_mask_gpio_press`
- `off=0x2e8994` `vaddr=0x006e8994` — `lineout_gpio`
- `off=0x2e89a4` `vaddr=0x006e89a4` — `audio_input_sw_gpio`
- `off=0x2e89b8` `vaddr=0x006e89b8` — `audio_input_sw_linein_gpio_value`
- `off=0x2e89dc` `vaddr=0x006e89dc` — `check_linein_gpio`

### network_only_not_s1_trigger (250)
- `off=0xe963` `vaddr=0x0040e963` — `rtspd_look_for_sess_by_sid`
- `off=0xe97e` `vaddr=0x0040e97e` — `rtspd_look_for_session_by_rtsp_req`
- `off=0xe9a1` `vaddr=0x0040e9a1` — `rtspd_new_session`
- `off=0xe9b3` `vaddr=0x0040e9b3` — `rtspd_init_session_by_req`
- `off=0xe9cd` `vaddr=0x0040e9cd` — `rtspd_free_session`
- `off=0x2d6734` `vaddr=0x006d6734` — `securePassthrough`
- `off=0x2d81cc` `vaddr=0x006d81cc` — `system nsd tdpd tdpc tmpd mactool wirelesstool protocol factory_status network dhcpc telemetry debug_tools dhcps cloud_iot wlan upgrade osd(avts) avts remote_debugger ffs tssd hub_`
- `off=0x2e8ae4` `vaddr=0x006e8ae4` — `onvif_name`
- `off=0x2e9ccc` `vaddr=0x006e9ccc` — `third_account`
- `off=0x2fe048` `vaddr=0x006fe048` — `/www/cert/onvif/private_key.pem`
- `off=0x3030a4` `vaddr=0x007030a4` — `device_confirm`
- `off=0x3030b4` `vaddr=0x007030b4` — `[HUB_MANAGE]cal_device_confirm error`
- `off=0x303180` `vaddr=0x00703180` — `client_cal_device_confirm`
- `off=0x3099a4` `vaddr=0x007099a4` — `/www/cert/onvif/public_key.pem`
- `off=0x30fe28` `vaddr=0x0070fe28` — `/upnpc/rtsp`
- `off=0x30ff94` `vaddr=0x0070ff94` — `/cet/rtsp`
- `off=0x316757` `vaddr=0x00716757` — `>tdpd tdpc tmpd mactool wirelesstool nifc dhcpc dhcps httpd httpd_v2 sntpc onvif system miniupnpc upgrade telemetry cloud_iot remote_debugger ffs tssd openapi hub_manage`
- `off=0x316dec` `vaddr=0x00716dec` — `                       onvif=11`
- `off=0x318670` `vaddr=0x00718670` — `[LocalCtrl]device_confirm = %s`
- `off=0x318aa4` `vaddr=0x00718aa4` — `calculate_device_confirm`
- `off=0x3194a8` `vaddr=0x007194a8` — `pake_register`
- `off=0x3197a0` `vaddr=0x007197a0` — `pake_share`
- `off=0x31a5d4` `vaddr=0x0071a5d4` — `[ONVIF]parameter wrong.`
- `off=0x31a5ec` `vaddr=0x0071a5ec` — `[ONVIF]malloc failed.`
- `off=0x31a604` `vaddr=0x0071a604` — `[ONVIF]len >= buf_size.`
- `off=0x31a61c` `vaddr=0x0071a61c` — `/onvif/dis_mode`
- `off=0x31a62c` `vaddr=0x0071a62c` — `[ONVIF]register ptrs to free failed `
- `off=0x31a654` `vaddr=0x0071a654` — `[ONVIF]malloc failed`
- `off=0x31a698` `vaddr=0x0071a698` — `onvif_str_append_chr`
- `off=0x31a6b0` `vaddr=0x0071a6b0` — `onvif_create_buf`
- `off=0x31a728` `vaddr=0x0071a728` — `http://%s:%d/onvif/device_service`
- `off=0x31a7ec` `vaddr=0x0071a7ec` — `[ONVIF]soap request content is NULL.`
- `off=0x31acf8` `vaddr=0x0071acf8` — `http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet`
- `off=0x31b328` `vaddr=0x0071b328` — `[ONVIF]ds read %s failed.`
- `off=0x31b360` `vaddr=0x0071b360` — `[ONVIF]supported event topic md(%d)-od(%d)-cd(%d)-id(%d)-pd(%d)-smart_det(%d)`
- `off=0x31b3dc` `vaddr=0x0071b3dc` — `[ONVIF]item == NULL`
- `off=0x31b3f0` `vaddr=0x0071b3f0` — `[ONVIF]malloc soap for event failed`
- `off=0x31b414` `vaddr=0x0071b414` — `[ONVIF]soap_event_create_tcp_conn failed`
- `off=0x31b440` `vaddr=0x0071b440` — `[ONVIF]add g_sub_list item failed`
- `off=0x31b4f8` `vaddr=0x0071b4f8` — `[ONVIF]add sublist failed`

## Matching ELF symbols

- `0x00000000` `IMP_System_UnBind` size=0 groups=factory_reset_state
- `0x00000000` `reboot` size=0 groups=factory_reset_state
- `0x0052d620` `wlan_manager_reboot` size=192 groups=factory_reset_state
- `0x0052e4dc` `wlan_manager_reboot_thread` size=424 groups=factory_reset_state
- `0x004cec3c` `Hash_SHA256_stream_AddData` size=60 groups=network_only_not_s1_trigger
- `0x004cebdc` `Hash_SHA256_stream_Begin` size=96 groups=network_only_not_s1_trigger
- `0x004cec78` `Hash_SHA256_stream_Finish` size=76 groups=network_only_not_s1_trigger
- `0x00000000` `IMP_Encoder_GetStream` size=0 groups=network_only_not_s1_trigger
- `0x00000000` `IMP_Encoder_PollingStream` size=0 groups=network_only_not_s1_trigger
- `0x00000000` `IMP_Encoder_ReleaseStream` size=0 groups=network_only_not_s1_trigger
- `0x00581590` `ffsAppendStream` size=96 groups=network_only_not_s1_trigger
- `0x005813b0` `ffsCreateInputStream` size=24 groups=network_only_not_s1_trigger
- `0x005813c8` `ffsCreateOutputStream` size=24 groups=network_only_not_s1_trigger
- `0x00584188` `ffsEncodeJsonQuotedStreamField` size=168 groups=network_only_not_s1_trigger
- `0x00584054` `ffsEncodeJsonStreamField` size=160 groups=network_only_not_s1_trigger
- `0x00581574` `ffsFlushStream` size=16 groups=network_only_not_s1_trigger
- `0x00589040` `ffsLogStream` size=140 groups=network_only_not_s1_trigger
- `0x005813e0` `ffsMoveStreamDataToEnd` size=120 groups=network_only_not_s1_trigger
- `0x0058bd14` `ffsParseHexStream` size=176 groups=network_only_not_s1_trigger
- `0x00581458` `ffsReadStream` size=64 groups=network_only_not_s1_trigger
- `0x005815f0` `ffsReuseInputStreamAsOutput` size=80 groups=network_only_not_s1_trigger
- `0x00581640` `ffsReuseOutputStreamAsOutput` size=80 groups=network_only_not_s1_trigger
- `0x00581584` `ffsRewindStream` size=12 groups=network_only_not_s1_trigger
- `0x0058155c` `ffsSetStreamToNull` size=24 groups=network_only_not_s1_trigger
- `0x005816e8` `ffsStreamIsEmpty` size=20 groups=network_only_not_s1_trigger
- `0x005816fc` `ffsStreamIsFull` size=20 groups=network_only_not_s1_trigger
- `0x0058bc94` `ffsStreamIsHex` size=128 groups=network_only_not_s1_trigger
- `0x00581710` `ffsStreamIsNull` size=24 groups=network_only_not_s1_trigger
- `0x005817b0` `ffsStreamMatchesStream` size=100 groups=network_only_not_s1_trigger
- `0x00581728` `ffsStreamMatchesString` size=136 groups=network_only_not_s1_trigger
- `0x00581520` `ffsWriteByteToStream` size=60 groups=network_only_not_s1_trigger
- `0x00581498` `ffsWriteStream` size=136 groups=network_only_not_s1_trigger
- `0x00581690` `ffsWriteStringToStream` size=88 groups=network_only_not_s1_trigger
- `0x006327ec` `rtspd_free_session` size=128 groups=network_only_not_s1_trigger
- `0x006328dc` `rtspd_init_session_by_req` size=376 groups=network_only_not_s1_trigger
- `0x00632b48` `rtspd_look_for_sess_by_sid` size=172 groups=network_only_not_s1_trigger
- `0x00632a54` `rtspd_look_for_session_by_rtsp_req` size=244 groups=network_only_not_s1_trigger
- `0x0063277c` `rtspd_new_session` size=112 groups=network_only_not_s1_trigger
- `0x007b8244` `FFS_CONFIGURATION_ENTRY_KEY_ALEXA_EVENT_GATEWAY_ENDPOINT` size=4 groups=physical_reset_inputs
- `0x00000000` `build_old_tss_provision_data` size=0 groups=provisioning_softap
- `0x0058218c` `ffsConvertDssWifiProvisioneeStateToApi` size=140 groups=provisioning_softap
- `0x00590410` `ffsDssDeserializeStartProvisioningSessionResponse` size=376 groups=provisioning_softap
- `0x0058be44` `ffsDssGetWifiProvisioneeStateString` size=176 groups=provisioning_softap
- `0x0058bef4` `ffsDssParseWifiProvisioneeState` size=392 groups=provisioning_softap
- `0x0058ace8` `ffsDssSerializeStartProvisioningSessionRequest` size=140 groups=provisioning_softap
- `0x00586c10` `ffsDssStartProvisioningSession` size=212 groups=provisioning_softap
- `0x00585fd0` `ffsGetWifiProvisioneeState` size=128 groups=provisioning_softap
- `0x00590a14` `ffsGetWifiProvisioneeStateString` size=296 groups=provisioning_softap
- `0x00586114` `ffsSetWifiProvisioneeCanProceed` size=124 groups=provisioning_softap
- `0x00585f54` `ffsSetWifiProvisioneeState` size=124 groups=provisioning_softap
- `0x005864d0` `ffsWifiProvisioneeCanGetWifiCredentials` size=32 groups=provisioning_softap
- `0x00586430` `ffsWifiProvisioneeCanPostWifiScanData` size=160 groups=provisioning_softap
- `0x005863b0` `ffsWifiProvisioneeCanProceed` size=128 groups=provisioning_softap
- `0x00590b3c` `ffsWifiProvisioneeStateIsTerminal` size=12 groups=provisioning_softap
- `0x0057e600` `ffsWifiProvisioneeTask` size=3220 groups=provisioning_softap
- `0x00532480` `ffs_onboarding_start` size=68 groups=provisioning_softap
- `0x005324c4` `ffs_onboarding_stop` size=68 groups=provisioning_softap
- `0x007de978` `g_onboarding_mode` size=4 groups=provisioning_softap
- `0x00536068` `get_cur_onboarding_mode` size=24 groups=provisioning_softap
- `0x00536050` `is_onboarding_ds_module_start` size=24 groups=provisioning_softap
- `0x00536d74` `is_onboarding_finished` size=80 groups=provisioning_softap
- `0x00536038` `is_onboarding_started` size=24 groups=provisioning_softap
- `0x00536020` `is_reonboarding` size=24 groups=provisioning_softap
- `0x0052eb78` `onboarding_cmd_init` size=32 groups=provisioning_softap
- `0x005365c4` `onboarding_ctx_init` size=80 groups=provisioning_softap
- `0x00536e8c` `onboarding_execute_shell_cmd` size=220 groups=provisioning_softap
- `0x0053609c` `onboarding_force_cfg_audio` size=28 groups=provisioning_softap
- `0x005360b8` `onboarding_module_start` size=1052 groups=provisioning_softap
- `0x005366a0` `onboarding_phy_link_status_change_handle` size=216 groups=provisioning_softap
- `0x00536778` `onboarding_restart` size=108 groups=provisioning_softap
- `0x00536080` `onboarding_set_start_flag` size=28 groups=provisioning_softap
- `0x005364f4` `onboarding_stop` size=208 groups=provisioning_softap
- `0x00530970` `set_exit_softap_fast_flag` size=24 groups=provisioning_softap
- `0x00536dc4` `set_onboarding_finished` size=128 groups=provisioning_softap
- `0x005323a0` `soft_ap_init` size=208 groups=provisioning_softap
- `0x00532470` `soft_ap_start` size=8 groups=provisioning_softap
- `0x00532478` `soft_ap_stop` size=8 groups=provisioning_softap
- `0x005308e4` `stop_exit_softap` size=140 groups=provisioning_softap
- `0x00532d18` `tss_onboarding_role` size=364 groups=provisioning_softap
- `0x0052d4f4` `wlan_manager_onboarding_start` size=292 groups=provisioning_softap
- `0x0052fc10` `disconnect_WiFi_ex` size=24 groups=wifi_events
- `0x0058bb00` `ffsConvertApiWifiScanResultToDss` size=136 groups=wifi_events
- `0x00580400` `ffsDisconnectFromSetupNetwork` size=252 groups=wifi_events
- `0x0058b44c` `ffsDssAddScanResultToSerializedPostWifiScanDataRequest` size=236 groups=wifi_events
- `0x005852d0` `ffsDssPostWifiScanDataAddScanResult` size=52 groups=wifi_events
- `0x0057dfa0` `ffsDssSerializeWifiScanResult` size=528 groups=wifi_events
- `0x0059122c` `ffsGetWifiScanResult` size=272 groups=wifi_events
- `0x00585038` `ffsRaspbianWifiManagerDisconnect` size=112 groups=wifi_events
- `0x00585364` `ffsWifiManagerDisconnect` size=24 groups=wifi_events
- `0x0064631c` `http_web_disconnect` size=120 groups=wifi_events
- `0x006c38a0` `mbedtls_ssl_conf_handshake_timeout` size=0 groups=wifi_events
- `0x006c3920` `mbedtls_ssl_handshake` size=0 groups=wifi_events
- `0x0052bfcc` `wlan_manager_init_reconnect_ctx` size=56 groups=wifi_events
- `0x0052ab94` `wlan_manager_sta_disconnect` size=80 groups=wifi_events
- `0x00537588` `wlan_manual_reconnect` size=104 groups=wifi_events
- `0x00531270` `wlan_sta_disconnect` size=148 groups=wifi_events
- `0x007d1f20` `esp32_driver_flag` size=4 groups=wifi_stack
- `0x005818d4` `ffsRaspbianConnectWithWpaSupplicant` size=904 groups=wifi_stack

## Priorities

- **P0** — Can unauthenticated 802.11 management/action traffic force NORMAL -> SoftAP/provisioning/factory state?  
  Evidence: repeatable state transition with no association/PSK/IP/physical action
- **P0** — Does repeated radio-induced link failure trigger an unsafe recovery/fallback policy?  
  Evidence: bounded disconnect/roam failure sequence followed by Tapo_Cam_* or config erasure
- **P1** — Is there a pre-association parser surface in driver/firmware/P2P/WPS/DPP handling?  
  Evidence: specific management/action frame class reaches a parser before association
- **CHAIN** — If provisioning is reached, can existing TPAP0 + Streamd findings complete the attack chain?  
  Evidence: already demonstrated in SETUP; trigger remains the missing link

## Interpretation rule

A crash/reboot is not a factory reset. A valid S1 result requires an observable and repeatable transition into provisioning/factory state (for example the camera advertising `Tapo_Cam_*`, losing prior binding/configuration, or equivalent state evidence) without association or physical action.
