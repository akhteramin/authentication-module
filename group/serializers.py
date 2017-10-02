from rest_framework import serializers
from .models import GroupList
from app.models import AppList


class GroupSerializer(serializers.ModelSerializer):
    appID = serializers.PrimaryKeyRelatedField(queryset=AppList.objects.filter())
    
    class Meta:
        model = GroupList
        fields = ('id', 'appID', 'groupID', 'description')
