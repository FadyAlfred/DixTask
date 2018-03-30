from django.urls import path, re_path
from rest_auth.registration.views import VerifyEmailView
from rest_auth.urls import LogoutView, UserDetailsView
from . import views

urlpatterns = [
    path('registration/', views.RegisterViewCustom.as_view(), name='account_signup'),
    path('login/', views.LoginView.as_view(), name='account_login'),
    path('logout/', LogoutView.as_view(), name='rest_logout'),
    re_path(r'^account-confirm-email/sent', views.django_rest_auth_null,
            name='account_email_verification_sent'),
    re_path(r'^account-confirm-email/(?P<key>[-:\w]+)/$', VerifyEmailView.as_view(),
            name='account_confirm_email'),
    path('password/reset/confirm/<str:uidb64>/<str:token>/', views.PasswordResetConfirmView.as_view(),
         name='password_reset_confirm'),
    path('user/', UserDetailsView.as_view(), name='rest_user_details'),
    path('phone/verify/<str:number>/', views.VerifyPhoneNumber.as_view(), name="phone_number_verification")
]
