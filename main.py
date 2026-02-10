import ota
import wifi


def conn_wifi(ssid: str, password: str):
    print(f"Connecting to: {ssid}")
    wifi.radio.connect(ssid, password)
    print(f"Connected to: {ssid}")


def main():    
    settings = ota.get_misc_settings()
    conn_wifi(settings["wifi_ssid"], settings["wifi_password"])
    # maybe someday # iot_cloud = IOT_Cloud(owner=settings["cloud_username"], token=settings["cloud_access_key"])
    tb_ota = ota.OverTheAirUpdate(repo_name=settings["gethub_repo_name"],  
                                  repo_owner=settings["gethub_repo_owner"],
                                  repo_access_token=settings["gethub_access_token"] )

    while True:
        try:
            if tb_ota.is_new_firmware_available():
                # New firmware is available, let's download it.
                tb_ota.download_firmware_files()    # and restart
            else:
                # Add your custom code here.
                pass
        except ConnectionError as e:
            # Handle request connection errors here, e.g. you might try to reconnect to Wi-Fi (Optional).
            pass   
        except ota.OverTheAirUpdateError as e:
            # Handle exceptions related to the firmware download process (Optional).
            pass   


if __name__ == '__main__':
    main()
