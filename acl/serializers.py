from rest_framework import serializers
from .models import ACL
from group.models import GroupList
from services.models import ServiceList


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = GroupList
        fields = ('id', 'groupID', 'description')


class ServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceList
        fields = ('id', 'serviceID', 'description')


class GetACLSerializer(serializers.ModelSerializer):
    group = GroupSerializer(read_only=True)
    service = ServiceSerializer(read_only=True)

    class Meta:
        model = ACL
        fields = ('id', 'group', 'service')


class ACLSerializer(serializers.ModelSerializer):
    class Meta:
        model = ACL
        fields = ('id', 'group', 'service')


class GetGroupSerializer(serializers.ModelSerializer):
    group = GroupSerializer(read_only=True)

    class Meta:
        model = ACL
        fields = ('id', 'group',)


class GetServiceSerializer(serializers.ModelSerializer):
    service = ServiceSerializer(read_only=True)

    class Meta:
        model = ACL
        fields = ('id', 'service',)
