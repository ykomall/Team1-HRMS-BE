import token
from django.shortcuts import render
import jwt
from rest_framework import viewsets
from .serializers import User_serializers
from .models import ApplyLeave, User, Manager
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
        print(email,password)
        # Authenticate user
        user=User.objects.filter(email=email).first()
        if user is None:
            response={
            "message":"No user found"
            }
            return Response(response,status.HTTP_200_OK)
        if user.email==email and pbkdf2_sha256.verify(password, user.password):
            # Successful authentication
            refresh = RefreshToken.for_user(user)
            access_token = jwt.encode( { 'email' : user.email }, "94CEDBC4AC5F94D4496E44691487A", algorithm='HS256')
            response={
                "message":"Successfully authenticated",
                "email": email,
                "access_token": access_token,
            }
            return Response(response, status.HTTP_200_OK)
        else:
            response={
                "message": "Invalid credentials."
            }
            # Failed authentication
            return Response(response,status.HTTP_200_OK)
        
class Leave(APIView):
    def post(self, request):
        # print("komal")
        leaveDesc = request.data.get('leaveDesc')
        fromDate = request.data.get('fromDate')
        toDate = request.data.get('toDate')
        selectManager = request.data.get('selectManager')
        verified = request.data.get('verified')
        headers = request.headers
        # Get Authorization token from headers
        authorization_token = headers.get('x-access-token')
        decoded_payload = jwt.decode(authorization_token, "94CEDBC4AC5F94D4496E44691487A", algorithms=['HS256'])
        if not decoded_payload:
            return Response(data={'error': 'Authorization header missing'}, status=status.HTTP_401_UNAUTHORIZED)
        emailget = decoded_payload.get('email')
        if not emailget:
            return Response(data={'error': 'Email missing in the token payload'}, status=status.HTTP_401_UNAUTHORIZED)
        # Check if email exists in user database
        if not User.objects.filter(email=emailget).exists():
            return Response(data={'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)


        user_instance = ApplyLeave.objects.create(
            leaveDesc=leaveDesc,
            fromDate=fromDate,
            toDate=toDate,
            selectManager=selectManager,
            verified=verified,
            user=request.data.get('email')
        )

        # Serialize the created user instance
        serializer = User_serializers(user_instance)
        
        return Response({"message": "Leave application created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)

class UserSignupView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        fullname = request.data.get('name')
        phone = request.data.get('phone')
        # Validate email and password
        if not email or not password:
            response={
                "message": "Both email and password are required."
            }
            return Response(response,status.HTTP_400_BAD_REQUEST)
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
    




class ManagerGet(APIView):
    def get(self, request):
        email = request.data.get('email')
        if not email :
            response={
                "message": "Email is required."
            }
            return Response(response,status.HTTP_400_BAD_REQUEST)

        if not Manager.objects.filter(email=email).exists():
            return Response(data={'error': 'Manager with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)

        print(email)

        users = User.objects.filter(manager=email)
        
        user_data = []
        for user in users:
            user_dict = {
                'email': user.email,
                'fullname': user.fullname,
                'phone': user.phone
            }
            user_data.append(user_dict)

        response_data = {

            'users': user_data
        }
        return Response(response_data, status=status.HTTP_200_OK)
    



class GrantLeave(APIView):
    def post(self, request):
        email = request.data.get('email')
        leaveId = request.data.get('leaveId')
        # leave  = ApplyLeave.objects.get
        grant = request.data.get('grant')

        if not email :
            response={
                "message": "Email is required."
            }
            return Response(response,status.HTTP_400_BAD_REQUEST)

        if not Manager.objects.filter(email=email).exists():
            return Response(data={'error': 'Manager with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
        if not ApplyLeave.objects.filter(id=leaveId).exists():
            return Response(data={'error': 'Invalid leave id'}, status=status.HTTP_404_NOT_FOUND)

        if(grant == "True"):
            apply_leave_instance = ApplyLeave.objects.get(id=leaveId)
            apply_leave_instance.verified = True  # Set verified to the new value
            apply_leave_instance.save() 
            return Response("Leave Granted", status=status.HTTP_200_OK)

        else:
            return Response("Leave Rejected", status=status.HTTP_200_OK)
