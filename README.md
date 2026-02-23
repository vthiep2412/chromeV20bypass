### Technical Analysis: Chrome v20 App-Bound Encryption Bypass

#### 1. Privilege Escalation & Impersonation
The script's core strength lies in its ability to manipulate Windows Access Tokens. 
- **SeDebugPrivilege:** The script enables this privilege to allow the process to inspect and interact with system-level processes.
- **LSASS Impersonation:** By duplicating the token of `lsass.exe`, the script gains the identity of the **NT AUTHORITY\SYSTEM** account. This is required to access the `Microsoft Software Key Storage Provider` where the Hardware-Bound keys are stored.
- **User Token Stealing:** It iterates through `explorer.exe` processes to "steal" the security context of the logged-in user. This allows it to call DPAPI `unprotect` functions as if it were the user, without needing the user's password.

#### 2. The Three-Layer Decryption Chain
The v20 protection is not a single lock, but a chain. This script follows the chain link-by-link:
1.  **Layer 1 (System DPAPI):** It decrypts the `app_bound_encrypted_key` from the 'Local State' file using SYSTEM-level DPAPI.
2.  **Layer 2 (User DPAPI):** The result of Layer 1 is then decrypted again using the **User's** DPAPI context (via the Explorer.exe token).
3.  **Layer 3 (CNG Key Storage):** It uses the Windows Cryptography Next Generation (CNG) API to interact with a specific key named `Google Chromekey1`.

#### 3. Final Reconstruction (The XOR & GCM Step)
Once the encrypted AES key is retrieved from the CNG provider:
- It applies a hardcoded **XOR mask** (`CCF8A1...`) to the decrypted bytes. 
- The resulting "Real Key" is used as the Master Key for an **AES-256-GCM** decryption.
- This Master Key is then applied to the `v20` prefixed blobs found in the SQLite `Login Data` database.

#### 4. Automated User Harvesting
Unlike basic scripts that only target the current user, this script iterates through `C:\Users`, automatically attempting to decrypt data for every profile found on the machine.
