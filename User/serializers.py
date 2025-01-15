from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import *
import re
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken

email_regex = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
password_regex = re.compile(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')

User = get_user_model()


class SignupSerializer(serializers.ModelSerializer):
    cpassword = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'first_name', 'last_name', 'cpassword']
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, attrs):
        # Get values using correct dict access
        email = attrs.get('email')
        password = attrs.get('password')
        cpassword = attrs.get('cpassword')
        first_name = attrs.get('first_name')
        last_name = attrs.get('last_name')

        # Check email format
        if not re.match(email_regex, email):
            raise serializers.ValidationError({'email': 'Invalid email format'})

        # Check if email exits
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError({'email': 'Email already exists'})

        # Check password format
        if not re.match(password_regex, password):
            raise serializers.ValidationError({
                'password': 'Password must contain at least 8 characters, '
                           'one uppercase, one lowercase, one number and '
                           'one special character'
            })

        # Check password and confirm password if matches
        if password != cpassword:
            raise serializers.ValidationError({'cpassword': 'Passwords do not match'})

        # Check the name lengths
        if len(first_name) < 2:
            raise serializers.ValidationError({'first_name': 'First name must be at least 2 characters'})

        if len(last_name) < 2:
            raise serializers.ValidationError({'last_name': 'Last name must be at least 2 characters'})

        return attrs

    def create(self, validated_data):
        # Remove cpassword from validated data
        validated_data.pop('cpassword', None)
        
        # Create user with hashed password
        user = User.objects.create_user(**validated_data)
        user.save()
        print (**validated_data)
        return user
            
    

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if not email or not password:
            raise serializers.ValidationError('Email and password are required.')

        # Authenticate using custom backend
        user = authenticate(email=email, password=password)

        if not user:
            raise serializers.ValidationError('Invalid credentials or user does not exist.')

        if not user.is_active:
            raise serializers.ValidationError('This account is inactive.')

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        return {
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        }



    
