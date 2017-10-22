from django.db import models


class Activity(models.Model):
    user = models.CharField(max_length=255,null=True)
    service=models.TextField(null=True)
    app = models.IntegerField(default=0)
    # data = models.TextField(null=True)
    createdAT = models.DateTimeField(auto_now_add=True, auto_now=False)
    class Meta:
        ordering = ['user']
        db_table = 'activity'
        default_permissions = []
