from django.db import models
from app.models import AppList


class GroupList(models.Model):
    appID = models.ForeignKey(AppList, on_delete=models.PROTECT, db_index=True)
    groupID = models.CharField(max_length=255)
    description = models.TextField(null=True)
    createdAT = models.DateTimeField(auto_now_add=True, auto_now=False)
    updatedAT = models.DateTimeField(auto_now_add=False, auto_now=True)

    class Meta:
        ordering = ['appID', 'groupID']
        db_table = "group_list"
        default_permissions = []
        unique_together = ('appID', 'groupID'),
