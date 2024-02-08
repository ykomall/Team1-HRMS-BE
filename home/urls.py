from django.urls import path, include
from home.views import Leave, NewUser, UserLoginView, UserSignupView, ManagerGet, GrantLeave,DeclineUser,LeaveBalance
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path("signup",UserSignupView.as_view()),
    path("login",UserLoginView.as_view(), name='login'),
    path("leave",Leave.as_view()),
    path("grantleave",GrantLeave.as_view()),
    path("manager",ManagerGet.as_view()),
    path("addEmployee",NewUser.as_view()),
    path("getnewEmployee",NewUser.as_view),
    path("getleaveapplication",GrantLeave.as_view()),
    path("declineEmployee",DeclineUser.as_view()),
    path("leave_balance",LeaveBalance.as_view()),
    path('api/token', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
]