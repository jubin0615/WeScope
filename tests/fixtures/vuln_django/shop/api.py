from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Order


class OrderAPI(APIView):
    permission_classes = [AllowAny]

    # expect: authz-idor, authz-no-auth-write
    def delete(self, request, pk):
        Order.objects.filter(pk=pk).delete()
        return Response(status=204)
