from rest_framework import viewsets
from auth.permissions import ServicePermission
from .models import ServiceList
from .serializers import ServiceSerializer

import logging
log = logging.getLogger(__name__)


class ServiceViewSet(viewsets.ModelViewSet):
    queryset = ServiceList.objects.all()
    serializer_class = ServiceSerializer
    permission_classes = (ServicePermission,)
