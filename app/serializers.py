from rest_framework import serializers
from .models import AppList


class AppSerializer(serializers.ModelSerializer):
    class Meta:
        model = AppList
        fields = ('id', 'appID', 'appName', 'description')