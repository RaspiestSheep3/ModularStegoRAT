import json
import base64
import socket
import sqlite3
from passlib.hash import argon2# type:ignore
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#Constants
DATABASE_NAME = "ModuleDatabase.db"
INCOMING_CONNECTION_HOST = "127.0.0.1"
INCOMING_CONNECTION_PORT = 12345
NUM_BYTES_PER_MODULE = 0 #TODO : Consider 3 instead - 2 provides 65536 which may not be highly scalable

def IncrementNonce(oldNonce : bytes, increment : int) -> bytes:
    oldNonceInt = int.from_bytes(oldNonce, byteorder="big")
    oldNonceInt = (oldNonceInt + increment) % (1 << 96) #Wraparound
    nonce = oldNonceInt.to_bytes(12, byteorder="big")
    return nonce

#Database management
conn = sqlite3.connect(DATABASE_NAME)
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS modules (
        moduleID INTEGER PRIMARY KEY,
        moduleName TEXT NOT NULL UNIQUE,
        moduleOwnerUsername TEXT NOT NULL,
        moduleDLLPath TEXT NOT NULL UNIQUE,
        moduleVersion TEXT,
        moduleDescription TEXT,
        moduleLastEdited TEXT NOT NULL,
        dependencies TEXT
    )
    """)

cursor.execute("""
    CREATE TABLE IF NOT EXISTS recognisedUsers (
        username TEXT PRIMARY KEY,
        password BLOB NOT NULL,
        publicKey BLOB NOT NULL UNIQUE           
    )
""")
conn.commit()

def HandleClient(clientSocket : socket.socket):
    #ECDHE
    bobPrivate = ec.generate_private_key(ec.SECP256R1())
    bobPublic = bobPrivate.public_key()

    #Sending alice public to bob the database
    bobPublicBytes = bobPublic.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    print("DERIVED BOB")

    bobTransmission = json.dumps({"Bob Public" : base64.b64encode(bobPublicBytes).decode()})
    clientSocket.send(bobTransmission.encode().ljust(1024, b"\0"))

    print("SNET BOB")

    aliceTransmission = json.loads(clientSocket.recv(1024).rstrip(b"\0").decode())
    alicePublicBytes = base64.b64decode(aliceTransmission["Alice Public"])
    alicePublic = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        alicePublicBytes
    )

    bobSharedSecret = bobPrivate.exchange(
        ec.ECDH(),
        alicePublic
    )

    AESKey = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Client-DB-Handshake",
    ).derive(bobSharedSecret)
    aes = AESGCM(AESKey)

    request = json.loads(clientSocket.recv(1024).rstrip(b"\0").decode())
    seedNonce = base64.b64decode(request["Nonce"])
    requestType = aes.decrypt(seedNonce, base64.b64decode(request["Type"]), None).decode()
    
    if(requestType == "DEFINE_NEW_USER"):
        username = aes.decrypt(IncrementNonce(seedNonce, 1), base64.b64decode(request["Username"]), None).decode()
        password = aes.decrypt(IncrementNonce(seedNonce, 2), base64.b64decode(request["Password"]), None).decode()
        publicKeyBytes = aes.decrypt(IncrementNonce(seedNonce, 3), base64.b64decode(request["Public Key"]), None)

        print(f"Type : {requestType} | {username} | {password} | {publicKeyBytes.hex()}")

        cursor.execute("SELECT * FROM recognisedUsers WHERE username = ?", (username, ))
        rows = cursor.fetchall()

        success = True
        if(rows == [] or rows == None):
            #The username is alr in use
            success = False

        try:
            cursor.execute("""
                INSERT INTO recognisedUsers (
                    username,
                    password,
                    publicKey
                ) VALUES (?, ?, ?)
            """,
            (
                username,
                argon2.hash(password),
                publicKeyBytes
            ))
            conn.commit()
        except Exception as e:
            print(f"Cursor Execution Error : {e}")
            success = False

        response = json.dumps({"Response" : base64.b64encode(aes.encrypt(IncrementNonce(seedNonce, 4), "SUCCESS".encode(), None)).decode()})
        clientSocket.send(response.encode().ljust(1024, b"\0"))

        clientSocket.shutdown(socket.SHUT_RDWR)
        clientSocket.close()
    
    elif(requestType == "UPLOAD_NEW_MODULE"):
        moduleName = aes.decrypt(IncrementNonce(seedNonce, 1), base64.b64decode(request["Module Name"]), None).decode()
        moduleDescription = aes.decrypt(IncrementNonce(seedNonce, 2), base64.b64decode(request["Module Description"]), None).decode()
        username = aes.decrypt(IncrementNonce(seedNonce, 3), base64.b64decode(request["Username"]), None).decode()
        password = aes.decrypt(IncrementNonce(seedNonce, 4), base64.b64decode(request["Password"]), None).decode()
        publicKeyBytes = aes.decrypt(IncrementNonce(seedNonce, 5), base64.b64decode(request["Public Key"]), None)
        dllSize = int(aes.decrypt(IncrementNonce(seedNonce, 6), base64.b64decode(request["DLL Size"]), None).decode())
        dependencies = json.loads(aes.decrypt(IncrementNonce(seedNonce, 7), base64.b64decode(request["Dependencies"]), None).decode())

        #Check 1 - Does this user alr exist?
        userExists = True
        cursor.execute("""
            SELECT * FROM recognisedUsers 
            WHERE username = ?
            AND publicKey = ?
        """, (username, publicKeyBytes))

        row = cursor.fetchone()
        if(row == None or row == [] or (not argon2.verify(password, row[1]))):
            userExists = False
        
        #Check 2 - does this module alr exist?
        moduleUnique = True
        cursor.execute("""
            SELECT * FROM modules
            WHERE moduleName = ?    
        """, (moduleName,))
        row = cursor.fetchone()
        if not(row == None or row == []):
            moduleUnique = False
        
        #Check 3 - do we have a spare moduleID ie have we gone past the limit?
        freeID = True
        cursor.execute("SELECT MAX(moduleID) FROM modules")
        lastModuleID = cursor.fetchone()[0]
        if(lastModuleID == (2**NUM_BYTES_PER_MODULE - 1)):
            freeID = False

        #Sending our info response
        responseMarker = "ACCEPTED" if (userExists and moduleUnique and freeID) else "DENIED"
        response = json.dumps({
            "Status" : responseMarker,
            "User Exists" : userExists,
            "Module Unique" : moduleUnique,
            "Free ID" : freeID
        }).encode()

        responseEncrypted = aes.encrypt(IncrementNonce(seedNonce, 8), response, None)
        clientSocket.send(responseEncrypted.ljust(1024, b"\0"))

#Accept users
incomingConnectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
incomingConnectionSocket.bind((INCOMING_CONNECTION_HOST, INCOMING_CONNECTION_PORT))
incomingConnectionSocket.listen(5)
clientSocket = None
while(clientSocket == None):
    clientSocket, addr = incomingConnectionSocket.accept()
    HandleClient(clientSocket)
    clientSocket = None