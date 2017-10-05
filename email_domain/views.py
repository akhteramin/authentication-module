from rest_framework import viewsets
from auth.permissions import EmailPermission
from .models import EmailDomain
from .serializers import EmailDomainSerializer

import logging
log = logging.getLogger(__name__)


class EmailViewSet(viewsets.ModelViewSet):
    # permission_classes = (EmailPermission,)
    queryset = EmailDomain.objects.all()
    serializer_class = EmailDomainSerializer
