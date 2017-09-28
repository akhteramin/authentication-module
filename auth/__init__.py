import os
from .settings import BASE_DIR

directory = BASE_DIR + '/logs'
try:
    if not os.path.exists(directory):
        os.makedirs(directory)
        print('logs folder created.\n')
    else:
        print('logs folder already exists.\n')
except:
    print('Could not create logs folder')