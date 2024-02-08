import token
from django.shortcuts import render
import jwt
import os
from rest_framework import viewsets
from .serializers import User_serializers
from .models import ApplyLeave, Moderator, User, Manager
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework.views import APIView,Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from passlib.hash import pbkdf2_sha256
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import datetime

# Create your views here.
class UserLoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        role = request.data.get('role')
        # # Authenticate user
        user=User.objects.filter(email=email).first()
        if user is None:
            response={
            "message":"No user found"
            }
            return Response(response,status.HTTP_200_OK)
        response={"user": user}
        if user.email==email and pbkdf2_sha256.verify(password, user.password):
        # #     # Successful authentication
            refresh = RefreshToken.for_user(user)
            access_token = jwt.encode( { 'email' : user.email }, os.environ.get("SECRET_KEY") , algorithm='HS256')
            response={
                "message":"Successfully authenticated",
                "email": email,
                "role":role,
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
        leaveDesc = request.data.get('leaveDesc')
        fromDate = request.data.get('fromDate')
        toDate = request.data.get('toDate')
        selectManager = request.data.get('selectManager')
        verified = request.data.get('verified')
        headers = request.headers
        authorization_token = headers.get('X-Access-Token')
        # Get Authorization token from headers
        decoded_payload = jwt.decode(authorization_token, os.environ.get("SECRET_KEY"), algorithms=['HS256'])
        if not decoded_payload:
            return Response(data={'error': 'Authorization header missing'}, status=status.HTTP_401_UNAUTHORIZED)
        emailget = decoded_payload.get('email')
        if not emailget:
            return Response(data={'error': 'Email missing in the token payload'}, status=status.HTTP_401_UNAUTHORIZED)
        # Check if email exists in user database
        if not User.objects.filter(email=emailget).exists():
            return Response(data={'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)
        fromdate=fromDate[0:10]
        todate=toDate[0:10]
        verified=False
        fromdate = datetime.strptime(fromdate, '%Y-%m-%d').date()
        todate=datetime.strptime(todate,'%Y-%m-%d').date()
        user_instance = ApplyLeave.objects.create(
            leaveDesc=leaveDesc,
            fromDate=fromdate,
            toDate=todate,
            selectManager=selectManager,
            verified=verified,
            user=emailget
        )
        # Serialize the created user instance
        serializer = User_serializers(user_instance)
        return Response({"message": "Leave application created successfully","data": serializer.data}, status=status.HTTP_201_CREATED)

class UserSignupView(APIView):
    def post(self, request):
        email = request.data.get('email')
        name = request.data.get('name')
        password = request.data.get('password')
        phone = request.data.get('phone')
        manager = request.data.get('manager')
        role = request.data.get('role')
        dob = request.data.get('dob')
        address = request.data.get('address')
        # Validate email and password
        if not email or not password:
            response={
                "message": "Both email and password are required."
            }
            return Response(response,status.HTTP_400_BAD_REQUEST)
        enc_pass = pbkdf2_sha256.encrypt(password, rounds = 12000, salt_size = 32)
        user_instance = Moderator.objects.create(
            email=email,
            password=enc_pass,
            name=name,
            phone=phone,
            manager=manager,
            role=role,
            dob=dob,
            address=address
        )
        user_instance.save()
        response = {"message": "User created successfully"}
        return Response(response, status=status.HTTP_201_CREATED)
    
class ManagerGet(APIView):
    def get(self, request):
        headers = request.headers
        authorization_token = headers.get('X-Access-Token')
        decoded_payload = jwt.decode(authorization_token, os.environ.get("SECRET_KEY"), algorithms=['HS256'])
        if not decoded_payload:
            return Response(data={'error': 'Authorization header missing'}, status=status.HTTP_401_UNAUTHORIZED)
        email = decoded_payload.get('email')
        if not email:
            return Response(data={'error': 'Email missing in the token payload'}, status=status.HTTP_401_UNAUTHORIZED)
        if not Manager.objects.filter(email=email).exists():
            return Response(data={'error': 'Manager with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)
        users = User.objects.filter(manager=email)
        user_data = []
        for user in users:
            user_dict = {
                'email': user.email,
                'name': user.name,
                'phone': user.phone
            }
            user_data.append(user_dict)
        response = {
            'users': user_data
        }
        return Response(response, status=status.HTTP_200_OK)
    
class GrantLeave(APIView):
    def get(self,request):
        headers = request.headers
        authorization_token = headers.get('X-Access-Token')
        decoded_payload = jwt.decode(authorization_token, os.environ.get("SECRET_KEY"), algorithms=['HS256'])
        if not decoded_payload:
            return Response(data={'error': 'Authorization header missing'}, status=status.HTTP_401_UNAUTHORIZED)
        email = decoded_payload.get('email')
        if not email:
            return Response(data={'error': 'Email missing in the token payload'}, status=status.HTTP_401_UNAUTHORIZED)
        if not Manager.objects.filter(email=email).exists():
            return Response(data={'error': 'Manager with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)
        leaves=ApplyLeave.objects.filter(selectManager=email)
        leave_data = []
        for leave in leaves:
            user_dict = {
                'leaveDesc': leave.leaveDesc,
                'fromDate': leave.fromDate,
                'toDate': leave.toDate,
                'user':leave.user,
            }
            leave_data.append(user_dict)
            response = {
            'users': leave_data
        }
        return Response(response, status=status.HTTP_200_OK)

    def put(self, request):
        email = request.data.get('email')
        leaveId = request.data.get('leaveId')
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

        if(grant == True):
            apply_leave_instance = ApplyLeave.objects.get(id=leaveId)
            start = apply_leave_instance.fromDate
            end = apply_leave_instance.toDate
            days = end- start
            print(days)
            if days.days < 0:
                
                return Response(data={'error': 'Not having enough leaves'}, status=status.HTTP_400_BAD_REQUEST)


            apply_leave_instance.verified = True  # Set verified to the new value
            apply_leave_instance.save() 
            user=User.objects.filter(email=apply_leave_instance.user).first()
            leave=int(user.leave_balance)-days
            user.leave_balance=leave
            user.save()
            return Response("Leave Granted", status=status.HTTP_200_OK)
        else:
            return Response("Leave Rejected", status=status.HTTP_200_OK)
        
class NewUser(APIView):
    def get(self,request):
        headers = request.headers
        authorization_token = headers.get('X-Access-Token')
        decoded_payload = jwt.decode(authorization_token, os.environ.get("SECRET_KEY"), algorithms=['HS256'])
        if not decoded_payload:
            return Response(data={'error': 'Authorization header missing'}, status=status.HTTP_401_UNAUTHORIZED)
        email = decoded_payload.get('email')
        if not email:
            return Response(data={'error': 'Email missing in the token payload'}, status=status.HTTP_401_UNAUTHORIZED)
        if not Manager.objects.filter(email=email).exists():
            return Response(data={'error': 'Manager with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)
        users=User.objects.filter(manager=email)
        user_data = []
        for user in users:
            user_dict = {
                'email': user.email,
                'name': user.name,
                'phone': user.phone
            }
            user_data.append(user_dict)
            response = {
            'users': user_data
            }
        return Response(response, status=status.HTTP_200_OK)

    def post(self, request):
        email = request.data.get('email')
        # Validate email and password
        user=Moderator.objects.filter(email=email).first()
        if not user:
            response={
                "message":"No such user present"
            }
            return Response(response,status.HTTP_400_BAD_REQUEST)
        user_instance = User.objects.create(
            email=user.email,
            password=user.password,
            name=user.name,
            phone=user.phone,
            manager=user.manager,
            role=user.role,
            dob=user.dob,
            address=user.address
        )
        user_instance.save()
        user.delete()
        # Serialize the created user instance
        response = {"message": "Employee added successfully"}
        return Response(response, status=status.HTTP_201_CREATED)

class DeclineUser(APIView):
    def delete(self, request):
        email = request.data.get('email')
        if not email:
            response={
                "message":"No email present"
            }
            return Response(response,status.HTTP_400_BAD_REQUEST)
        # Validate email and password
        user=Moderator.objects.filter(email=email).first()
        if not user:
            response={
                "message":"No such user present"
            }
            return Response(response,status.HTTP_400_BAD_REQUEST)
        user.delete()
        # Serialize the created user instance
        response = {"message": "Employee Declined successfully"}
        return Response(response, status=status.HTTP_201_CREATED)

class LeaveBalance(APIView):
    def get(self,request):
        headers = request.headers
        authorization_token = headers.get('X-Access-Token')
        decoded_payload = jwt.decode(authorization_token, os.environ.get("SECRET_KEY"), algorithms=['HS256'])
        if not decoded_payload:
            return Response(data={'error': 'Authorization header missing'}, status=status.HTTP_401_UNAUTHORIZED)
        email = decoded_payload.get('email')
        if not email:
            return Response(data={'error': 'Email missing in the token payload'}, status=status.HTTP_401_UNAUTHORIZED)
        if not Manager.objects.filter(email=email).exists():
            return Response(data={'error': 'Manager with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)
        user=User.objects.filter(email=email).first()
        response={
            "leave_balance":user.leave_balance
        }
        return Response(response,status=status.HTTP_201_CREATED)
    
