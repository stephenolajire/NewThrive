from django.shortcuts import render
from .serializers import *
from rest_framework.views import APIView
from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.contrib.auth import get_user_model

User = get_user_model()

class SignUpView (APIView):
    permission_classes = [AllowAny]
    def post (self, request):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response ({'message': 'user registration is successful'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors)


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
