from rest_framework import serializers
from .models import EmailDomain


class EmailDomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailDomain
        fields = ('id', 'domain')