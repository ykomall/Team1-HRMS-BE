from django.db import models
from passlib.hash import pbkdf2_sha256

# Create your models here.
class User(models.Model):
    email = models.CharField(max_length = 50,default='',primary_key=True,null=False)
    name = models.CharField(max_length = 50,default='',null=False)
    password = models.CharField(max_length = 256,default='',null=False)
    phone = models.CharField(max_length = 10,default='',null=False)
    manager = models.CharField(max_length = 30,default='',null=False)
    role = models.CharField(max_length=32,default='',null=False)
    dob = models.CharField(max_length=32,default='',null=False)
    address = models.CharField(max_length=128,default='',null=False)
    leave_balance=models.IntegerField(default=30,null=False)
    
class Moderator(models.Model):
    email = models.CharField(max_length = 50,default='',primary_key=True,null=False)
    name = models.CharField(max_length = 50,default='',null=False)
    password = models.CharField(max_length = 256,default='',null=False)
    phone = models.CharField(max_length = 10,default='',null=False)
    manager = models.CharField(max_length = 30,default='',null=False)
    role = models.CharField(max_length=32,default='',null=False)
    dob = models.CharField(max_length=32,default='',null=False)
    address = models.CharField(max_length=128,default='',null=False)
    def __str__(self) :
        return self.email
    
class Manager(models.Model):
    email = models.CharField(max_length = 50,default='',primary_key=True,null=False)
    name = models.CharField(max_length = 50,default='',null=False)
    def __str__(self) :
        return self.email

class ApplyLeave(models.Model):
    leaveDesc = models.CharField(max_length = 250,default='')
    fromDate = models.CharField(max_length = 250,default='',null=False)
    toDate = models.CharField(max_length = 250,default='',null=False)
    selectManager = models.CharField(max_length = 30,default='',null=False)
    user=models.ForeignKey(User,on_delete=models.CASCADE,null=True)
    verified = models.CharField(max_length=16,default='Pending',null=False)
    
    
