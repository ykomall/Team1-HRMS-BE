from rest_framework import serializers
from .models import User,Moderator

class User_serializers(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__' 
class Moderator_serializers(serializers.ModelSerializer):
    class Meta:
        model = Moderator
        fields='__all__'