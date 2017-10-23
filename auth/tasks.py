from __future__ import absolute_import, unicode_literals
import random
from celery.decorators import task
from activity.models import Activity

@task(name="save_activity")
def save_activity(loginID, appID,service,dataset):
    print("activity adding")
    saveactivitylog = Activity(user=loginID, service=service,app=appID,data=dataset)
    saveactivitylog.save()
    return {"message":"activity added"}
