from rest_framework import serializers
from .models import User
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.contrib.auth.tokens import default_token_generator as token_generator

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'full_name', 'email', 'password', 'role', 'confirm_password']
    
    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        return data

    def create(self, validated_data):
        user = User(
            username=validated_data['username'],
            full_name=validated_data['full_name'],
            email=validated_data['email'],
            role=validated_data['role'],
        )
        user.set_password(validated_data['password'])
        user.save()
        
        # Send verification email
        self.send_verification_email(user)
        return user
    
    def send_verification_email(self, user):
        token = token_generator.make_token(user)
        uid = urlsafe_base64_encode(user.pk.encode())
        verification_url = f"http://localhost:8000/users/verify-email/{uid}/{token}/"
        
        subject = "Verify your email"
        message = render_to_string('email_verification.html', {'verification_url': verification_url})
        send_mail(subject, message, 'no-reply@myapp.com', [user.email])

class LoginSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'password']