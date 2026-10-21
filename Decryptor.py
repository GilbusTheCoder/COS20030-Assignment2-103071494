from pathlib import Path
import base64
import hashlib
import hmac
import re

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

SALT = bytes([191, 235, 30, 86, 251, 205, 151, 59,
            178, 25, 2, 36, 48, 165, 120, 67, 0,
            61, 86, 68, 210, 30, 98, 185, 212, 241,
            128, 231, 230, 195, 57, 65 ])

SOURCE      = Path(__file__).with_name("Settings.cs")
source_text = SOURCE.read_text(encoding="utf-8-sig")
fields      = dict(re.findall(
    r'public\s+static\s+string\s+(\w+)\s*=\s*"([^"]*)"\s*;',
    source_text ))

master_key  = base64.b64decode(fields["Key"]).decode("utf-8")
derived     = hashlib.pbkdf2_hmac(
    "sha1", master_key.encode("utf-8"),
    SALT, 50000, dklen=96 )

aes_key     = derived[:32]
auth_key    = derived[32:96]

def decrypt(encrypted_str:str) -> str:
    data = base64.b64decode(encrypted_str)
    mac         = data[:32]
    iv          = data[32:48]
    ciphertext  = data[48:]

    calc_mac    = hmac.new(auth_key, data[32:], hashlib.sha256).digest()

    if not hmac.compare_digest(mac, calc_mac):
        raise ValueError("HMAC Validation failed...")

    cipher      = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext   = cipher.decrypt(ciphertext)

    return unpad(plaintext, AES.block_size).decode("utf-8")


targets = [ "Version", "Hosts", "Ports", "Anti", "Install", "MTX", "BDOS", "Group" ]
print("----------------- RECOVERED MW CFG -----------------")

for name in targets:
    if name not in fields:
        print(f"{name}: None")
        continue

    try:
        print(f"{name}: {decrypt(fields[name])}")
    except Exception as err:
        print(f"{name}: Error - {err}...")