from rest_framework import serializers
from .models import ServiceList


class ServiceSerializer(serializers.ModelSerializer):
    appID = serializers.IntegerField(min_value=1)
    
    class Meta:
        model = ServiceList
        fields = ('id', 'appID', 'serviceID', 'description')
