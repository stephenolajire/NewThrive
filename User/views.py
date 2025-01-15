from rest_framework.generics import RetrieveAPIView, UpdateAPIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from .serializers import *
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from django.conf import settings
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.hashers import make_password
from rest_framework.permissions import AllowAny
from django.http import HttpResponseRedirect
from django.shortcuts import redirect

User = get_user_model()

class SignUpView(APIView):
    permission_classes = [AllowAny]  # Allow anyone to access this view

    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token_generator = PasswordResetTokenGenerator()
            token = token_generator.make_token(user)
            verification_link = f"{settings.FRONTEND_URL}/confirm_email/{uid}/{token}"

            mail_subject = 'Activate your account'
            message = f"Click the link to activate your account: {verification_link}"
            send_mail(mail_subject, message, settings.EMAIL_HOST_USER, [user.email])
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        # Log the validation errors
        print(serializer.errors)  # For debugging purposes
        return Response({"message":"Email has already been used"}, status=status.HTTP_400_BAD_REQUEST)
    

class VerifyEmailAddressView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, uid, token):
        """Handle email verification"""
        try:
            uid = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"message": "Invalid activation link"}, status=status.HTTP_400_BAD_REQUEST)
        
        token_generator = PasswordResetTokenGenerator()
        if user is not None and token_generator.check_token(user, token):
            user.verified = True
            user.save()
            return Response({"message": "email confirmed!"}, status=status.HTTP_200_OK) 
        
        else:
            return Response({"message": "Invalid token!"}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            tokens = serializer.validated_data.get('tokens')
            return Response(
                {'message': 'Login successful', 'tokens': tokens},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
