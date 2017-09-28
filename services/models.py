from django.db import models


class ServiceList(models.Model):
    moduleID = models.CharField(max_length=255)
    serviceID = models.CharField(unique=True, max_length=255)
    description = models.TextField(null=True)
    createdAT = models.DateTimeField(auto_now_add=True, auto_now=False)
    updatedAT = models.DateTimeField(auto_now_add=False, auto_now=True)

    class Meta:
        ordering = ['serviceID']
        db_table = "service_list"
        default_permissions = []
