import psutil

def get_processes():
    process_dict = {}

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid']):
        try:
            process_dict[proc.info['pid']] = {
                "pid": proc.info['pid'],
                "ppid": proc.info['ppid'],
                "name": proc.info['name'] or "Unknown",
                "path": proc.info['exe'] or "N/A"
            }

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return process_dict