import platform
import subprocess

def get_hwid():
    if platform.system() != "Windows": return "None"

    cmd = subprocess.Popen("wmic useraccount where name='%username%' get sid", stdout=subprocess.PIPE, shell=True)
    suppost_sid, _ = cmd.communicate()
    system_hwid = suppost_sid.split(b'\n')[1].strip()

    return system_hwid.decode()