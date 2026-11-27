from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Order


class OrderAPI(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        Order.objects.filter(pk=pk, user=request.user).delete()
        return Response(status=204)
