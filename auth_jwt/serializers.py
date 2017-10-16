from rest_framework import serializers
from .models import Auth, Token
from app.models import AppList
from email_domain.models import EmailDomain


class TokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = Token
        fields = ('id', 'user', 'token', 'deviceID')


class BaseSerializer(serializers.ModelSerializer):
    loginID = serializers.EmailField(min_length=12)
    password = serializers.CharField(min_length=8, write_only=True)
    appID = serializers.IntegerField()

    def validate_loginID(self, email):
        domain = email.split("@")[-1]
        try:
            email_domain = EmailDomain.objects.get(domain=domain)
            return email
        except Exception as e:
            print(e)
            raise serializers.ValidationError("Invalid Email Domain!") 


    class Meta:
        model = Auth
        fields = ('id', 'loginID', 'password', 'appID', 'deviceID', 'is_active')


class ReadOnlySerializer(serializers.ModelSerializer):
    class Meta:
        model = Auth
        fields = ('id', 'loginID', 'appID', 'deviceID', 'is_active', 'createdAT', 'updatedAT')


class ReadUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Auth
        fields = ( 'loginID', 'appID', 'deviceID', 'is_active', 'createdAT', 'updatedAT')


class LoginSerializer(serializers.Serializer):
    loginID = serializers.CharField(min_length=5)
    password = serializers.CharField(min_length=8, write_only=True)
    appID = serializers.IntegerField(min_value=1)
    deviceID = serializers.CharField()


class ChangePasswordSerializer(serializers.Serializer):
    loginID = serializers.CharField(min_length=5)
    appID = serializers.IntegerField(min_value=1)
    old_password = serializers.CharField(min_length=8, write_only=True)
    new_password = serializers.CharField(min_length=8, write_only=True)


class SetPasswordSerializer(serializers.Serializer):
    loginID = serializers.CharField(min_length=5)
    password = serializers.CharField(min_length=8, write_only=True)
    appID = serializers.IntegerField(min_value=1)


class DeactiveSerializer(serializers.Serializer):
    loginID = serializers.CharField(min_length=5)
    appID = serializers.IntegerField(min_value=1)
