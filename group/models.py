from django.db import models


class GroupList(models.Model):
    appID = models.CharField(max_length=255)
    groupID = models.CharField(max_length=255)
    description = models.TextField(null=True)
    createdAT = models.DateTimeField(auto_now_add=True, auto_now=False)
    updatedAT = models.DateTimeField(auto_now_add=False, auto_now=True)

    class Meta:
        ordering = ['appID', 'groupID']
        db_table = "group_list"
        unique_together = ('appID', 'groupID'),
        default_permissions = []
