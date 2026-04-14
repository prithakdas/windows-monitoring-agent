import wmi

def get_services():
    c = wmi.WMI()
    service_list = []

    for service in c.Win32_Service():
        try:
            service_info = {
                "name": service.Name,
                "display_name": service.DisplayName,
                "path": service.PathName,
                "start_mode": service.StartMode  # Auto, Manual, Disabled
            }
            service_list.append(service_info)

        except Exception:
            continue

    return service_list