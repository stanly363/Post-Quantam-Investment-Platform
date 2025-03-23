import base64
from argon2 import PasswordHasher
from django.contrib.auth.hashers import BasePasswordHasher
from django.utils.crypto import constant_time_compare
from django.utils.encoding import force_bytes, force_str

class CustomArgon2Hasher(BasePasswordHasher):
    """
    Custom Argon2 Hasher for Django using `argon2-cffi`.
    """
    algorithm = 'argon2_custom'

    # Custom Argon2 Configuration (Higher security settings)
    ph = PasswordHasher(
        time_cost=4,        # Increases computational cost (default: 2)
        memory_cost=102400, # Memory usage in KB (default: 512)
        parallelism=2,      # Parallelism (default: 2)
        hash_len=32,        # Length of the output hash
        salt_len=16         # Length of the generated salt
    )

    def encode(self, password, salt):
        """
        Encode the password using Argon2.
        """
        assert password is not None
        assert salt and '$' not in salt  # Ensure no accidental `$` symbols
        hashed_password = self.ph.hash(password)
        return f"{self.algorithm}${hashed_password}"

    def verify(self, password, encoded):
        """
        Verify the password using Argon2.
        """
        algorithm, hash_str = encoded.split('$', 1)
        try:
            return self.ph.verify(hash_str, password)
        except Exception:
            return False

    def safe_summary(self, encoded):
        """
        Display a partial summary for better security in logs.
        """
        algorithm, hash_str = encoded.split('$', 1)
        return {
            'algorithm': algorithm,
            'hash': hash_str[:6] + '...' + hash_str[-6:]  # Partial hash for security
        }

    def must_update(self, encoded):
        """
        Rehash the password if Argon2's settings have improved.
        """
        algorithm, hash_str = encoded.split('$', 1)
        try:
            return self.ph.check_needs_rehash(hash_str)
        except Exception:
            return True  # Assume update is needed if check fails

    def salt(self):
        """
        Generate a secure salt using Argon2’s in-built method.
        """
        return base64.b64encode(self.ph.hash("generate_salt").encode('utf-8'))[:16].decode('utf-8')
