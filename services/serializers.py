from rest_framework import serializers
from .models import ServiceList


class ServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceList
        fields = ('id', 'appID', 'serviceID', 'description')
