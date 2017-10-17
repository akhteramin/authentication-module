from __future__ import absolute_import, unicode_literals
import random
from celery.decorators import task
import requests
import json

HEADERS = {
    "Content-type": "application/json",
    "Accept": "application/json",
    "X-CSRFToken": "BJeWR32Q6AgETCGGIRz9V0lrxh1qwWOQb2pd2wbd6haZVOq6AuJo7ZOZDz895cbY"
}

@task(name="sum_two_numbers")
def add(x, y):
    print("heelo there")
    post_data = {'appName': "test_app",
                 'description': "app no description"};

    response_data = requests.post('http://localhost:8080/auth/api/v1/app/', headers=HEADERS, data=json.dumps(post_data))

    return response_data.json()

@task(name="multiply_two_numbers")
def mul(x, y):
 total = x * (y * random.randint(3, 100))
 return total

@task(name="sum_list_numbers")
def xsum(numbers):
 return sum(numbers)