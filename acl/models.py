from django.db import models
from group.models import GroupList
from services.models import ServiceList


class ACL(models.Model):
    group = models.ForeignKey(GroupList, on_delete=models.PROTECT, db_index=True)
    service = models.ForeignKey(ServiceList, on_delete=models.PROTECT)
    createdAT = models.DateTimeField(auto_now_add=True, auto_now=False)
    updatedAT = models.DateTimeField(auto_now_add=False, auto_now=True)

    class Meta:
        ordering = ['group', 'service']
        db_table = "acl"
        default_permissions = []
        unique_together = ('group', 'service')