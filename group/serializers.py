from rest_framework import serializers
from .models import GroupList


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = GroupList
        fields = ('id', 'appID', 'groupID', 'description')
