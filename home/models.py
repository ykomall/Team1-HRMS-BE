from django.db import models

# Create your models here.
class User(models.Model):
    email = models.CharField(max_length = 50,default='')
    fullname = models.CharField(max_length = 50,default='')
    password = models.CharField(max_length = 20,default='')
    phone = models.CharField(max_length = 10,default='')
    def __str__(self) :
        return self.email
    

