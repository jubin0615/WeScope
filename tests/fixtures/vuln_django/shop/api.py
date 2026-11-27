from django.contrib.auth.models import User
from rest_framework import permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Order


class OrderAPI(APIView):
    permission_classes = [AllowAny]

    # expect: authz-idor, authz-no-auth-write
    def delete(self, request, pk):
        Order.objects.filter(pk=pk).delete()
        return Response(status=204)


class StaffUserAPI(APIView):
    permission_classes = [IsAuthenticated]      # 로그인만 확인한다. 관리자 확인이 아니다

    # expect: authz-admin-route
    def delete(self, request, pk):
        User.objects.filter(pk=pk).delete()
        return Response(status=204)


# expect: authz-idor
@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def order_note(request, pk):
    order = Order.objects.get(pk=pk)
    return Response({"id": order.id})
