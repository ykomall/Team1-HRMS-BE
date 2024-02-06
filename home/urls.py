from django.urls import path, include
from home.views import Leave, UserLoginView, UserSignupView
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path("signup",UserSignupView.as_view()),
    path("login",UserLoginView.as_view()),
    path("leave",Leave.as_view()),
    path('api/token', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
]