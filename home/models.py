from django.db import models
from passlib.hash import pbkdf2_sha256


# Create your models here.
class User(models.Model):
    email = models.CharField(max_length = 50,default='')
    fullname = models.CharField(max_length = 50,default='')
    password = models.CharField(max_length = 256,default='')
    phone = models.CharField(max_length = 10,default='')
    def __str__(self) :
        return self.email
    
    # def verify_password(self, raw_password):
    #     return pbkdf2_sha256.verify(raw_password, self.password)
    

