from rest_framework import serializers
from .models import UserGroup
from group.models import GroupList
from auth_jwt.models import Auth


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = GroupList
        fields = ('id', 'appID', 'groupID', 'description')


class AuthSerializer(serializers.ModelSerializer):
    class Meta:
        model = Auth
        fields = ('id', 'loginID', 'appID')


class GetUserGroupSerializer(serializers.ModelSerializer):
    group = GroupSerializer(read_only=True)
    user = AuthSerializer(read_only=True)

    class Meta:
        model = UserGroup
        fields = ('id', 'group', 'user')


class UserGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserGroup
        fields = ('id', 'group', 'user')


class GetGroupSerializer(serializers.ModelSerializer):
    group = GroupSerializer(read_only=True)

    class Meta:
        model = UserGroup
        fields = ('id', 'group',)


class GetUserSerializer(serializers.ModelSerializer):
    user = AuthSerializer(read_only=True)

    class Meta:
        model = UserGroup
        fields = ('id', 'user',)
