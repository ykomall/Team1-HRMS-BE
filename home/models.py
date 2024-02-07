from django.db import models
from passlib.hash import pbkdf2_sha256


# Create your models here.
class User(models.Model):
    email = models.CharField(max_length = 50,default='')
    fullname = models.CharField(max_length = 50,default='')
    password = models.CharField(max_length = 256,default='')
    phone = models.CharField(max_length = 10,default='')
    manager = models.CharField(max_length = 30,default='')
    def __str__(self) :
        return self.email
    
class Manager(models.Model):
    email = models.CharField(max_length = 50,default='')
    fullname = models.CharField(max_length = 50,default='')
    password = models.CharField(max_length = 256,default='')
    phone = models.CharField(max_length = 10,default='')
    def __str__(self) :
        return self.email
    
    

class ApplyLeave(models.Model):
    leaveDesc = models.CharField(max_length = 250,default='')
    fromDate = models.DateTimeField()
    toDate = models.DateTimeField()
    selectManager = models.CharField(max_length = 30,default='')
    user = models.CharField(max_length = 30,default='')
    verified = models.BooleanField(default=False)
    
    
