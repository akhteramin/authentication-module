from rest_framework import serializers
from .models import GroupList


class GroupSerializer(serializers.ModelSerializer):
    appID = serializers.IntegerField(min_value=1)
    
    class Meta:
        model = GroupList
        fields = ('id', 'appID', 'groupID', 'description')
