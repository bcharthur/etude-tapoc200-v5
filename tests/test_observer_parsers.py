from observer.wifi_probe import parse_netsh_networks


def test_parse_netsh_english_and_french_channel():
    text = """
SSID 1 : Home
    BSSID 1 : aa:bb:cc:dd:ee:ff
         Signal : 88%
         Canal : 6
SSID 2 : Tapo_Cam_Test
    BSSID 1 : 11:22:33:44:55:66
         Signal : 50%
         Channel : 11
"""
    rows = parse_netsh_networks(text)
    assert rows[0]["ssid"] == "Home"
    assert rows[0]["channel"] == 6
    assert rows[1]["ssid"] == "Tapo_Cam_Test"
    assert rows[1]["channel"] == 11
