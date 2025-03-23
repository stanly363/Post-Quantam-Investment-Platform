from django.test import TestCase
from decimal import Decimal
from .crypto_utils import (
    encrypt_balance, decrypt_balance,
    encrypt_transaction_data, decrypt_transaction_data,
    encrypt_message, decrypt_message,
    generate_new_key, get_server_keys
)
import base64
import os
from django.contrib.auth.hashers import make_password, check_password

class EncryptionTests(TestCase):

    def setUp(self):
        # Generate mock server keys for testing
        self.server_key = generate_new_key()
        self.server_algorithm, self.server_pub, self.server_priv = get_server_keys()

    # --- Balance Encryption Tests ---

    def test_encrypt_decrypt_balance(self):
        balance = Decimal('12345.67')
        encrypted_balance = encrypt_balance(balance)
        decrypted_balance = decrypt_balance(encrypted_balance)
        self.assertEqual(balance, decrypted_balance)

    def test_encrypt_balance_invalid(self):
        balance = Decimal('9999.99')
        encrypted_balance = encrypt_balance(balance)
        # Tampering with data should break decryption
        encrypted_balance = encrypted_balance[:-5] + "00000"
        with self.assertRaises(Exception):
            decrypt_balance(encrypted_balance)

    # --- Transaction Encryption Tests ---

    def test_encrypt_decrypt_transaction(self):
        sender = "alice"
        recipient = "bob"
        amount = 1000.50

        ephemeral_pub, ciphertext, signature = encrypt_transaction_data(
            sender, recipient, amount, self.server_pub
        )
        decrypted_data = decrypt_transaction_data(
            ephemeral_pub, ciphertext, signature, self.server_priv
        )

        self.assertEqual(decrypted_data['sender'], sender)
        self.assertEqual(decrypted_data['recipient'], recipient)
        self.assertEqual(decrypted_data['amount'], amount)

    def test_transaction_invalid_signature(self):
        sender = "alice"
        recipient = "bob"
        amount = 2000.00

        ephemeral_pub, ciphertext, signature = encrypt_transaction_data(
            sender, recipient, amount, self.server_pub
        )
        # Tamper with ciphertext
        ciphertext = ciphertext[:-5] + "AAAAA"

        with self.assertRaises(Exception):
            decrypt_transaction_data(ephemeral_pub, ciphertext, signature, self.server_priv)

    # --- Message Encryption Tests ---

    def test_encrypt_decrypt_message(self):
        message = "This is a secure message."
        encrypted_message = encrypt_message(message)
        decrypted_message = decrypt_message(encrypted_message)
        self.assertEqual(message, decrypted_message)

    def test_message_decrypt_tampered_data(self):
        message = "Hello Secure World!"
        encrypted_message = encrypt_message(message)
        # Tampering should cause decryption failure
        encrypted_message = encrypted_message[:-5] + "12345"
        with self.assertRaises(Exception):
            decrypt_message(encrypted_message)

    # --- Key Generation Tests ---

    def test_generate_new_key(self):
        key = generate_new_key()
        self.assertTrue(key.is_active)
        self.assertEqual(key.algorithm, "MLKEM1024")

    def test_server_key_existence(self):
        self.assertIsNotNone(get_server_keys())


class Argon2HasherTests(TestCase):

    from django.contrib.auth.hashers import make_password, check_password

    def test_argon2_password_hashing(self):
        password = "SuperSecurePassword123!"
        hashed_password = make_password(password)
        self.assertTrue(check_password(password, hashed_password))
        self.assertFalse(check_password("WrongPassword", hashed_password))


