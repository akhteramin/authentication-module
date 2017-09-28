from django.db import models
from app.models import AppList


class ServiceList(models.Model):
    appID = models.ForeignKey(AppList, on_delete=models.CASCADE, db_index=True)
    serviceID = models.CharField(unique=True, max_length=255)
    description = models.TextField(null=True)
    createdAT = models.DateTimeField(auto_now_add=True, auto_now=False)
    updatedAT = models.DateTimeField(auto_now_add=False, auto_now=True)

    class Meta:
        ordering = ['appID', 'serviceID']
        db_table = "service_list"
        default_permissions = []
        unique_together = ('appID', 'serviceID'),
