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
        moduleOwnerUsername TEXT NOT NULL,
        moduleDLLPath TEXT NOT NULL UNIQUE,
        moduleVersion TEXT,
        moduleDescription TEXT,
        moduleLastEdited TEXT NOT NULL
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

#Accept users
incomingConnectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
incomingConnectionSocket.bind((INCOMING_CONNECTION_HOST, INCOMING_CONNECTION_PORT))
incomingConnectionSocket.listen(5)
clientSocket = None
while(clientSocket == None):
    clientSocket, addr = incomingConnectionSocket.accept()

#ECDHE
bobPrivate = ec.generate_private_key(ec.SECP256R1())
bobPublic = bobPrivate.public_key()

#Sending alice public to bob the database
bobPublicBytes = bobPublic.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)

bobTransmission = json.dumps({"Bob Public" : base64.b64encode(bobPublicBytes).decode()})
clientSocket.send(bobTransmission.encode().ljust(1024, b"\0"))

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


conn.close()