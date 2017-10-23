from __future__ import absolute_import
import os
from .settings import BASE_DIR
from .celery import app as celery_app

directory = BASE_DIR + '/logs'
try:
    if not os.path.exists(directory):
        os.makedirs(directory)
        print('logs folder created.\n')
except:
    print('Could not create logs folder')