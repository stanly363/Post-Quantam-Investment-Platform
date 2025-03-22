from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

ROLE_CHOICES = [
    ('client', 'Client'),
    ('advisor', 'Financial Advisor'),
    # Admin accounts are typically created separately.
]

class RegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)
    role = forms.ChoiceField(choices=ROLE_CHOICES)

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2", "role")

class TransactionForm(forms.Form):
    recipient = forms.CharField(max_length=150)
    amount = forms.DecimalField(max_digits=12, decimal_places=2)

class InvestForm(forms.Form):
    shares = forms.DecimalField(max_digits=12, decimal_places=2, min_value=0.01)

class UserUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email']