from rest_framework import serializers
from .models import Activity
from app.models import AppList


class ActivitySerializer(serializers.ModelSerializer):
    # appID = serializers.PrimaryKeyRelatedField(queryset=AppList.objects.filter())
    
    class Meta:
        model = Activity
        fields = ('id', 'user', 'app', 'service', 'data', 'createdAT')
