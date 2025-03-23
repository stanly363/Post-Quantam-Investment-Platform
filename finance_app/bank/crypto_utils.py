import os
import base64
import time
from decimal import Decimal
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from quantcrypt.kem import MLKEM_1024  

ALGORITHM = "MLKEM1024"

# Caching server keys to avoid redundant queries
_server_keys_cache = None

def get_server_keys():
    """Retrieve or generate server keys (cached for efficiency)."""
    global _server_keys_cache
    if _server_keys_cache:
        return _server_keys_cache

    from .models import PQServerKey
    key = PQServerKey.objects.filter(is_active=True).first()
    if not key:
        key = generate_new_key()
    
    _server_keys_cache = (
        key.algorithm, 
        base64.b64decode(key.public_key), 
        base64.b64decode(key.private_key)
    )
    return _server_keys_cache

def generate_new_key():
    """Generates and saves a new PQServerKey."""
    from .models import PQServerKey
    kem_algorithm = MLKEM_1024()
    public_key, private_key = kem_algorithm.keygen()
    return PQServerKey.objects.create(
        algorithm=ALGORITHM,
        public_key=base64.b64encode(public_key).decode('utf-8'),
        private_key=base64.b64encode(private_key).decode('utf-8'),
        created_at=int(time.time()),
        is_active=True,
    )


def derive_symmetric_key(salt: bytes, info: bytes, server_priv=None) -> bytes:
    """Derives a symmetric key using HKDF with the active server key."""
    if server_priv is None:
        _, _, server_priv = get_server_keys()

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
        backend=default_backend()
    ).derive(server_priv)

# ====================== ENCRYPTION & DECRYPTION HELPERS ======================
def encrypt_data(value: str, salt: bytes, info: bytes) -> str:
    """Encrypts data using AES-GCM."""
    symmetric_key = derive_symmetric_key(salt, info)
    plaintext = value.encode('utf-8')
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    combined = nonce + encryptor.tag + ciphertext
    return base64.b64encode(combined).decode('utf-8')

def decrypt_data(encrypted_value: str, salt: bytes, info: bytes, server_priv=None) -> str:
    """Decrypts AES-GCM encrypted data."""
    symmetric_key = derive_symmetric_key(salt, info, server_priv)
    combined = base64.b64decode(encrypted_value)
    nonce = combined[:12]
    tag = combined[12:28]
    ciphertext = combined[28:]

    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext.decode('utf-8')

# ====================== BALANCE ENCRYPTION / DECRYPTION ======================
def encrypt_balance(balance: Decimal) -> str:
    return encrypt_data(str(balance), b'balance_salt', b'balance encryption')

def decrypt_balance(encrypted_balance: str) -> Decimal:
    return Decimal(decrypt_data(encrypted_balance, b'balance_salt', b'balance encryption'))

# ====================== FIELD ENCRYPTION / DECRYPTION ======================
def encrypt_field(value: str, salt: bytes, info: bytes) -> str:
    return encrypt_data(value, salt, info)

def decrypt_field(encrypted_value: str, salt: bytes, info: bytes, server_priv=None) -> str:
    return decrypt_data(encrypted_value, salt, info, server_priv)

# ====================== MESSAGE ENCRYPTION / DECRYPTION ======================
def encrypt_message(message: str) -> str:
    """Encrypts a message with key ID tracking for key rotation support."""
    from .models import PQServerKey
    key_obj = PQServerKey.objects.filter(is_active=True).first() or generate_new_key()

    key_id = key_obj.id
    encrypted_data = encrypt_data(message, b'message_salt', b'message encryption')
    return f"{key_id}:{encrypted_data}"

def decrypt_message(encrypted_message: str) -> str:
    """Decrypts a message using the key ID for compatibility with rotated keys."""
    key_id_str, encoded_data = encrypted_message.split(":", 1)
    key_id = int(key_id_str)

    # Retrieve the correct key based on the stored key ID
    from .models import PQServerKey
    try:
        key_obj = PQServerKey.objects.get(id=key_id)
    except PQServerKey.DoesNotExist:
        raise Exception("Encryption key not found.")

    server_priv = base64.b64decode(key_obj.private_key)
    return decrypt_data(encoded_data, b'message_salt', b'message encryption', server_priv)
