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
        user=User.objects.filter(email=email).first()
        print(email)
        if user is None:
            response={
            "message":"No user found"
            }
            return Response(response,status.HTTP_404_NOT_FOUND)
        if user.email==email and pbkdf2_sha256.verify(password, user.password):
            refresh = RefreshToken.for_user(user)


            access_token = jwt.encode( { 'email' : user.email },"94CEDBC4AC5F94D4496E44691487A", algorithm='HS256')

            serializer = User_serializers(user)
            manager=False
            if user.role=="Manager":
                manager=True

            response={
                "message": "Successfully authenticated",
                "email": email,

                "access_token":access_token,
                "success":True,
                "manager":manager
            }
            return Response(response, status.HTTP_200_OK)
        else:
            response={
                "success":False,
                "message": "Invalid credentials."
            }
        return Response(response,status.HTTP_404_NOT_FOUND)
        
class Leave(APIView):
    def post(self, request):
        leaveDesc = request.data.get('leaveDesc')
        fromDate = request.data.get('fromDate')
        toDate = request.data.get('toDate')
        selectManager = request.data.get('selectManager')
        headers = request.headers
        authorization_token = headers.get('Authorization')
        if not authorization_token:
            response={
            'success': False
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)
        # # Get Authorization token from headers

        decoded_payload = jwt.decode(authorization_token,"94CEDBC4AC5F94D4496E44691487A", algorithms=['HS256'])

        if not decoded_payload:
            response={
                'error': 'Authorization header missing'
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)
        emailget = decoded_payload.get('email')
        if not emailget:
            response={
                'error': 'Email missing in the token payload'
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)
        # # Check if email exists in user database
        if not User.objects.filter(email=emailget).exists():
            response={
                'error': 'User with this email does not exist'
            }
            return Response(response, status=status.HTTP_404_NOT_FOUND)
        fromdate=fromDate[0:10]
        todate=toDate[0:10]
        from_date_str = fromDate[0:10]
        to_date_str = toDate[0:10]
        from_date = datetime.strptime(from_date_str, "%Y-%m-%d").date()
        to_date = datetime.strptime(to_date_str, "%Y-%m-%d").date()
        days = (to_date - from_date).days
        user = User.objects.get(email=emailget)
        leave_balance = user.leave_balance
        if days < 0 or days > leave_balance:
            response={
                'error': 'leave not available'
            }
            return Response(response, status=status.HTTP_404_NOT_FOUND)
        user_instance = ApplyLeave.objects.create(
            leaveDesc=leaveDesc,
            fromDate=fromdate,
            toDate=todate,
            selectManager=selectManager,
            user_id=emailget
        )
        user_instance.save()
        response={
                "message": "Leave application created successfully"
            }
        return Response(response, status=status.HTTP_201_CREATED)

class UserSignupView(APIView):
    def post(self, request):
        email = request.data.get('email')
        name = request.data.get('name')
        password = request.data.get('password')
        phone = request.data.get('phone')
        manager = request.data.get('selectManager')
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

        authorization_token = headers.get('Authorization')
        if not authorization_token:
            response={
            'success': False
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)

        decoded_payload = jwt.decode(authorization_token, "94CEDBC4AC5F94D4496E44691487A", algorithms=['HS256'])


        if not decoded_payload:
            response={
                'error': 'Authorization header missing'
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)
        email = decoded_payload.get('email')
        if not email:
            response={
                'error': 'Email missing in the token payload'
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)
        if not Manager.objects.filter(email=email).exists():
            response={
                'error': 'Manager with this email does not exist'
            }
            return Response(response, status=status.HTTP_404_NOT_FOUND)
        manager_name=Manager.objects.filter(email=email).first().name
        users = User.objects.filter(manager=manager_name)
        user_data = []
        for user in users:
            user_dict = {
                'email': user.email,
                'name': user.name,
                'manager': user.manager,
                'role': user.role
            }
            user_data.append(user_dict)
        response = {
            'users': user_data
        }
        return Response(response, status=status.HTTP_200_OK)
    
class GrantLeave(APIView):
    def get(self,request):
        headers = request.headers
        authorization_token = headers.get('Authorization')
        if not authorization_token:
            response={
            'success': False
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)

        decoded_payload = jwt.decode(authorization_token,"94CEDBC4AC5F94D4496E44691487A", algorithms=['HS256'])


        if not decoded_payload:
            response={
                'error': 'Authorization header missing'
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)
        email = decoded_payload.get('email')
        if not email:
            response={
                'error': 'Email missing in the token payload'
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)
        if not Manager.objects.filter(email=email).exists():
            response={
                'error': 'Manager with this email does not exist'
            }
            return Response(response, status=status.HTTP_404_NOT_FOUND)
        manager_name=Manager.objects.filter(email=email).first().name
        leaves=ApplyLeave.objects.filter(selectManager=manager_name)
        leave_data = []
        for leave in leaves:
            if leave.verified=="Pending":
                user=User.objects.filter(email=leave.user_id).first()
                user_dict = {
                    'id':leave.id,
                    'leaveDesc': leave.leaveDesc,
                    'fromDate': leave.fromDate,
                    'toDate': leave.toDate,
                    'user':user.name,
                    'role':user.role
                }
                leave_data.append(user_dict)
        response = {
            'leaves': leave_data
        }
        return Response(response, status=status.HTTP_200_OK)

    def put(self, request):
        leaveId = request.data.get('leaveId')
        grant = request.data.get('grant')
        if not ApplyLeave.objects.filter(id=leaveId).exists():
            return Response(data={'error': 'Invalid leave id'}, status=status.HTTP_404_NOT_FOUND)
        if(grant == True):
            apply_leave_instance = ApplyLeave.objects.get(id=leaveId)
            start = apply_leave_instance.fromDate
            end = apply_leave_instance.toDate
            start = datetime.strptime(start, '%Y-%m-%d')
            end = datetime.strptime(end, '%Y-%m-%d')
            days = end-start
            user=User.objects.filter(email=apply_leave_instance.user_id).first()
            leave=int(user.leave_balance)-days.days
            user.leave_balance=leave
            user.save()
            apply_leave_instance.verified = "Approved"
            apply_leave_instance.save()
            return Response("Leave Granted", status=status.HTTP_200_OK)
        else:
            apply_leave_instance = ApplyLeave.objects.get(id=leaveId)
            apply_leave_instance.verified = "Rejected"
            apply_leave_instance.save()
            return Response("Leave Rejected", status=status.HTTP_200_OK)
class NewUser(APIView):
    def get(self,request):
        response={}
        headers = request.headers
        authorization_token = headers.get('Authorization')
        if not authorization_token:
            response={
            'success': False
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)

        decoded_payload = jwt.decode(authorization_token, "94CEDBC4AC5F94D4496E44691487A", algorithms=['HS256'])


        if not decoded_payload:
            response = {
            'error': 'Authorization header missing'
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)
        email = decoded_payload.get('email')
        if not email:
            response = {
            'error': 'Email missing in the token payload'
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)
        if not Manager.objects.filter(email=email).exists():
            response = {
            'error': 'Manager with this email does not exist'
            }
            return Response(response, status=status.HTTP_404_NOT_FOUND)
        manager_name=Manager.objects.filter(email=email).first().name
        users=Moderator.objects.filter(manager=manager_name) 
        user_data = []
        for user in users:
            user_dict = {
                'email': user.email,
                'name': user.name,
                'manager': user.manager,
                'role': user.role
            }
            user_data.append(user_dict)
            response = {
                'message':'Data send',
            'users': user_data
            }
        return Response(response, status=status.HTTP_200_OK)

    def post(self, request):
        response={}
        email = request.data.get('email')
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
        response = {"message": "Employee added successfully"}
        return Response(response, status=status.HTTP_201_CREATED)

class DeclineUser(APIView):
    def post(self, request):
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
        authorization_token = headers.get('Authorization')
        if not authorization_token:
            response={
            'success': False
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)

        decoded_payload = jwt.decode(authorization_token,"94CEDBC4AC5F94D4496E44691487A" , algorithms=['HS256'])

        if not decoded_payload:
            response = {
            'error': 'Authorization header missing'
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)
        email = decoded_payload.get('email')
        if not email:
            response = {
            'error': 'Email missing in the token payload'
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)
        user=User.objects.filter(email=email).first()
        my_leaves = ApplyLeave.objects.filter(user_id=email)
        on_Hold,applied = 0,0
        for row in my_leaves:
            from_date = datetime.strptime(row.fromDate.split(' ')[0], "%Y-%m-%d").date()
            to_date = datetime.strptime(row.toDate.split(' ')[0], "%Y-%m-%d").date()
            days = (to_date - from_date).days
            if row.verified == "Pending":
                on_Hold = on_Hold + days
            if row.verified=="Approved":
                applied=applied+days
        response={
            "leave_balance":user.leave_balance,
            "onhold" : on_Hold,
            "applied":applied
        }
        return Response(response,status=status.HTTP_201_CREATED)
    
class ProfileCard(APIView):
    def get(self,request):
        response={}
        headers = request.headers
        authorization_token = headers.get('Authorization')

        if not authorization_token:
            response={
            'success': False
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)
        

        decoded_payload = jwt.decode(authorization_token, "94CEDBC4AC5F94D4496E44691487A" , algorithms=['HS256'])

        if not decoded_payload:
            response={
            'error': 'Authorization header missing'
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)
        email = decoded_payload.get('email')
        user=User.objects.filter(email=email).first()
        serializer = User_serializers(user)
        response={
            "user":serializer.data
        }
        return Response(response,status=status.HTTP_200_OK)

class GetManager(APIView):
    def get(self,request):
        response={}
        manager=Manager.objects.all()
        manager_data = []
        for manager in manager:
            manager_data.append(manager.name)
        response = {
            'manager': manager_data
        }
        return Response(response, status=status.HTTP_200_OK)
