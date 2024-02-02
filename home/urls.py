from django.urls import path, include
from home.views import UserLoginView, UserSignupView

urlpatterns = [
    path("signup",UserSignupView.as_view()),
    path("login",UserLoginView.as_view()),
]