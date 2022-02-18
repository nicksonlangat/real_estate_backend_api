from django.urls import path
from .views import (
    PasswordTokenCheckAPI,
    RegisterUser,
    RequestPasswordResetEmail,
    SetNewPasswordAPIView,
    UpdatePassword, UserList,
    login_view,
    refresh_token_view
)

urlpatterns = [
    path('register',RegisterUser.as_view(),name='register'),
    path('login',login_view,name='login'),
    path('refresh/token',refresh_token_view,name='refresh'),
    path('change/password', UpdatePassword.as_view(),name='change_password'),
    path('password-reset-email/', RequestPasswordResetEmail.as_view(), name='password-reset-email'),
    path('reset-password/<uidb64>/<token>/', PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-complete/', SetNewPasswordAPIView.as_view(), name='password-reset-complete'),
    path('users', UserList.as_view()),
]