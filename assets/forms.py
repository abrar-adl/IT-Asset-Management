from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")
    
    # def save(self, commit=True):
    #     """
    #     user.email = self.cleaned_data.get("email")
    #     Overrides the base implementation to ensure the email field is saved.
    #     """
    #     user = super().save(commit=False)
    #     user.email = self.cleaned_data["email"]
    #     if commit:
    #         user.save()
    #         self._save_m2m()
    #     return user