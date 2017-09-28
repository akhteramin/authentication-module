from django.db import models


class AppList(models.Model):
    appName = models.CharField(max_length=255, unique=True)
    description = models.TextField(null=True)
    createdAT = models.DateTimeField(auto_now_add=True, auto_now=False)
    updatedAT = models.DateTimeField(auto_now_add=False, auto_now=True)

    class Meta:
        ordering = ['appName']
        db_table = "app_list"
        default_permissions = []