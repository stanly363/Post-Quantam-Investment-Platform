from django.db import models
from django.contrib.auth.models import User
from decimal import Decimal
from .crypto_utils import encrypt_balance, decrypt_balance
from .forms import UserUpdateForm
ROLE_CHOICES = [
    ('client', 'Client'),
    ('advisor', 'Financial Advisor'),
    ('admin', 'System Administrator'),
]

# User Profile – remains for registration/logins.
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='client')
    advisor = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='clients_assigned')
    encrypted_balance = models.TextField(default='')  

    def save(self, *args, **kwargs):
        if not self.encrypted_balance:
            self.encrypted_balance = encrypt_balance(Decimal('10000'))  # default cash balance
        super().save(*args, **kwargs)

    @property
    def balance(self):
        try:
            return decrypt_balance(self.encrypted_balance)
        except Exception:
            return Decimal('0')

    @balance.setter
    def balance(self, value):
        self.encrypted_balance = encrypt_balance(value)

    def __str__(self):
        return self.user.username

# Investment Portfolio (for more detailed cash balance and holdings)
class Portfolio(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    cash_balance = models.DecimalField(max_digits=12, decimal_places=2, default=10000)
    def __str__(self):
        return f"Portfolio of {self.user.username}"

# Stock model – stores available stocks.
class Stock(models.Model):
    ticker = models.CharField(max_length=10, unique=True)
    company_name = models.CharField(max_length=100)
    last_price = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    last_updated = models.DateTimeField(null=True, blank=True)
    def __str__(self):
        return f"{self.ticker} - {self.company_name}"

# Each Holding represents shares of a stock in a Portfolio.
class Holding(models.Model):
    portfolio = models.ForeignKey(Portfolio, on_delete=models.CASCADE, related_name='holdings')
    stock = models.ForeignKey(Stock, on_delete=models.CASCADE)
    shares = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    def __str__(self):
        return f"{self.shares} shares of {self.stock.ticker}"

# Investment transactions (buy/sell)
class InvestmentTransaction(models.Model):
    portfolio = models.ForeignKey(Portfolio, on_delete=models.CASCADE, related_name='transactions')
    stock = models.ForeignKey(Stock, on_delete=models.CASCADE)
    transaction_type = models.CharField(max_length=4, choices=(('BUY', 'Buy'), ('SELL', 'Sell')))
    shares = models.DecimalField(max_digits=12, decimal_places=2)
    price = models.DecimalField(max_digits=12, decimal_places=2)
    timestamp = models.DateTimeField(auto_now_add=True)
    def get_formatted_timestamp(self):
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    def __str__(self):
        return f"{self.transaction_type} {self.shares} of {self.stock.ticker} @ {self.price}"

# Existing Transaction model for (encrypted) bank-like transfers (if still used)
class Transaction(models.Model):
    sender = models.ForeignKey(User, related_name="sent_transactions", on_delete=models.CASCADE)
    recipient = models.ForeignKey(User, related_name="received_transactions", on_delete=models.CASCADE)
    ephemeral_ciphertext = models.TextField()   # base64 encoded ephemeral public key
    ciphertext = models.TextField()             # base64 encoded AES‑encrypted data
    hmac_signature = models.TextField()           # base64 encoded HMAC signature
    timestamp = models.BigIntegerField()
    def get_formatted_timestamp(self):
        from datetime import datetime
        return datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S")
    def __str__(self):
        return f"Transaction {self.id}: {self.sender} -> {self.recipient}"
    @property
    def amount_value(self):
        from .crypto_utils import get_server_keys, decrypt_transaction_data
        try:
            _, _, server_priv = get_server_keys()
            data = decrypt_transaction_data(self.ephemeral_ciphertext, self.ciphertext, self.hmac_signature, server_priv)
            return data.get("amount")
        except Exception:
            return None

# Audit log for admin actions
class AuditLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    event = models.TextField()
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    def get_formatted_timestamp(self):
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    def __str__(self):
        return f"{self.get_formatted_timestamp()} - {self.event}"

# Encryption key management
class PQServerKey(models.Model):
    algorithm = models.CharField(max_length=50)
    public_key = models.TextField()
    private_key = models.TextField()
    created_at = models.BigIntegerField()
    is_active = models.BooleanField(default=True)
    def __str__(self):
        status = "Active" if self.is_active else "Archived"
        return f"{self.algorithm} key created at {self.created_at} ({status})"

class PortfolioHistory(models.Model):
    portfolio = models.ForeignKey(Portfolio, on_delete=models.CASCADE, related_name='history')
    timestamp = models.DateTimeField()  # We'll store the time truncated to the minute
    total_value = models.DecimalField(max_digits=12, decimal_places=2)

    def __str__(self):
        return f"{self.portfolio.user.username} at {self.timestamp}: {self.total_value}"

class Message(models.Model):
    sender = models.ForeignKey(User, related_name="sent_messages", on_delete=models.CASCADE)
    recipient = models.ForeignKey(User, related_name="received_messages", on_delete=models.CASCADE)
    encrypted_text = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def get_formatted_timestamp(self):
        return self.timestamp.strftime("%H:%M:%S")

    def __str__(self):
        return f"Message from {self.sender} to {self.recipient} at {self.get_formatted_timestamp()}"
    
