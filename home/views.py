from django.shortcuts import render
from rest_framework import viewsets
from .serializers import User_serializers
from .models import User
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework.views import APIView,Response

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

        if user.email==email and user.password==password:
            # Successful authentication
            response={
                "message":"Successfully authenticated",
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
        user_instance = User.objects.create(
            email=email,
            password=password,
            fullname=fullname,
            phone=phone
        )

        # Serialize the created user instance
        serializer = User_serializers(user_instance)
        
        response = {"message": "User created successfully", "data": serializer.data}
        return Response(response, status=status.HTTP_201_CREATED)