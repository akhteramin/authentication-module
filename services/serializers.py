from rest_framework import serializers
from .models import ServiceList
from app.models import AppList


class ServiceSerializer(serializers.ModelSerializer):
    appID = serializers.PrimaryKeyRelatedField(queryset=AppList.objects.filter())
    
    class Meta:
        model = ServiceList
        fields = ('id', 'appID', 'serviceID', 'description')
