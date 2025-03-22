import os
import base64
import time
from decimal import Decimal
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ALGORITHM = "X25519"  # Our chosen algorithm

def get_server_keys():
    from .models import PQServerKey  # local import to avoid circular dependency
    key = PQServerKey.objects.filter(is_active=True).first()
    if not key:
        key = generate_new_key()
    return key.algorithm, base64.b64decode(key.public_key), base64.b64decode(key.private_key)

def generate_new_key():
    from .models import PQServerKey
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    key = PQServerKey.objects.create(
        algorithm=ALGORITHM,
        public_key=base64.b64encode(public_bytes).decode('utf-8'),
        private_key=base64.b64encode(private_bytes).decode('utf-8'),
        created_at=int(time.time()),
        is_active=True,
    )
    return key

def encrypt_balance(balance: Decimal) -> str:
    _, _, server_priv = get_server_keys()
    symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'balance_salt',
        info=b'balance encryption',
        backend=default_backend()
    ).derive(server_priv)
    plaintext = str(balance).encode('utf-8')
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    combined = nonce + encryptor.tag + ciphertext
    return base64.b64encode(combined).decode('utf-8')

def decrypt_balance(encrypted_balance: str) -> Decimal:
    _, _, server_priv = get_server_keys()
    symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'balance_salt',
        info=b'balance encryption',
        backend=default_backend()
    ).derive(server_priv)
    combined = base64.b64decode(encrypted_balance)
    nonce = combined[:12]
    tag = combined[12:28]
    ciphertext = combined[28:]
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return Decimal(plaintext.decode('utf-8'))

def encrypt_transaction_data(sender: str, recipient: str, amount: float, server_pub_bytes: bytes):
    timestamp = int(time.time())
    tx_data = f"{sender}|{recipient}|{amount}|{timestamp}"
    plaintext = base64.b64encode(tx_data.encode('utf-8'))
    server_pub = x25519.X25519PublicKey.from_public_bytes(server_pub_bytes)
    ephemeral_private = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()
    shared_secret = ephemeral_private.exchange(server_pub)
    symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"x25519 transaction encryption",
        backend=default_backend()
    ).derive(shared_secret)
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    combined = nonce + encryptor.tag + ciphertext
    transaction_ciphertext_b64 = base64.b64encode(combined).decode('utf-8')
    h = crypto_hmac.HMAC(symmetric_key, hashes.SHA256(), backend=default_backend())
    h.update(combined)
    signature = h.finalize()
    hmac_signature_b64 = base64.b64encode(signature).decode('utf-8')
    ephemeral_pub_bytes = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    ephemeral_pub_b64 = base64.b64encode(ephemeral_pub_bytes).decode('utf-8')
    return ephemeral_pub_b64, transaction_ciphertext_b64, hmac_signature_b64

def decrypt_transaction_data(ephemeral_pub_b64: str, transaction_ciphertext_b64: str, hmac_signature_b64: str, server_priv_bytes: bytes):
    ephemeral_pub_bytes = base64.b64decode(ephemeral_pub_b64)
    ephemeral_public = x25519.X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
    server_private = x25519.X25519PrivateKey.from_private_bytes(server_priv_bytes)
    shared_secret = server_private.exchange(ephemeral_public)
    symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"x25519 transaction encryption",
        backend=default_backend()
    ).derive(shared_secret)
    combined = base64.b64decode(transaction_ciphertext_b64)
    nonce = combined[:12]
    tag = combined[12:28]
    ciphertext = combined[28:]
    h = crypto_hmac.HMAC(symmetric_key, hashes.SHA256(), backend=default_backend())
    h.update(combined)
    h.verify(base64.b64decode(hmac_signature_b64))
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    raw = base64.b64decode(plaintext).decode('utf-8')
    parts = raw.split('|')
    return {
        "sender": parts[0],
        "recipient": parts[1],
        "amount": float(parts[2]),
        "timestamp": int(parts[3])
    }

def encrypt_message(message: str) -> str:
    """
    Encrypts a message string using a symmetric key derived from the server's private key.
    Uses a fixed salt and info string to ensure a consistent key.
    """
    _, _, server_priv = get_server_keys()
    symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'message_salt',       # Fixed salt for message encryption
        info=b'message encryption', # Fixed info string
        backend=default_backend()
    ).derive(server_priv)
    plaintext = message.encode('utf-8')
    nonce = os.urandom(12)  # AES-GCM nonce length
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    combined = nonce + encryptor.tag + ciphertext
    return base64.b64encode(combined).decode('utf-8')

def decrypt_message(encrypted_message: str) -> str:
    """
    Decrypts an encrypted message and returns the plaintext.
    """
    _, _, server_priv = get_server_keys()
    symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'message_salt',
        info=b'message encryption',
        backend=default_backend()
    ).derive(server_priv)
    combined = base64.b64decode(encrypted_message)
    nonce = combined[:12]
    tag = combined[12:28]
    ciphertext = combined[28:]
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')