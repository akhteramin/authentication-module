from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view


@api_view(["GET"])
def http400(request):
    return Response(status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
def http403(request):
    return Response(status=status.HTTP_403_FORBIDDEN)


@api_view(["GET"])
def http404(request):
    return Response(status=status.HTTP_404_NOT_FOUND)


@api_view(["GET"])
def http500(request):
    return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)