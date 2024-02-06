from django.shortcuts import render
from rest_framework import viewsets
from .serializers import User_serializers
from .models import User
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework.views import APIView,Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from passlib.hash import pbkdf2_sha256
from rest_framework_simplejwt.tokens import RefreshToken

# Create your views here.
class UserLoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        # Validate email and password
        if not email or not password:
            response={
                {"message": "Both email and password are required."}
            }
            return Response(
                response,
                status.HTTP_400_BAD_REQUEST
            )
        # Authenticate user
        user=User.objects.filter(email=email).first()
        


        if user.email==email and pbkdf2_sha256.verify(password, user.password):
            # Successful authentication

            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            response={
                "message":"Successfully authenticated",
                
                "access_token": access_token,
            }
            return Response(response, status.HTTP_200_OK)
        else:
            response={
                "message": "Invalid credentials."
            }
            # Failed authentication
            return Response(
                response,
                status.HTTP_401_UNAUTHORIZED
            )
        



class UserSignupView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        fullname = request.data.get('fullname')
        phone = request.data.get('phone')

        # Validate email and password
        if not email or not password:
            response={
                {"message": "Both email and password are required."}
            }
            return Response(
                response,
                status.HTTP_400_BAD_REQUEST
            )
        
        enc_pass = pbkdf2_sha256.encrypt(password, rounds = 12000, salt_size = 32)

        user_instance = User.objects.create(
            email=email,
            password=enc_pass,
            fullname=fullname,
            phone=phone
        )


        # Serialize the created user instance
        serializer = User_serializers(user_instance)
        
        response = {"message": "User created successfully", "data": serializer.data}
        return Response(response, status=status.HTTP_201_CREATED)