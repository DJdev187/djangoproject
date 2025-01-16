from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import LoginView, LogoutView
from django.conf import settings
from django.conf.urls.static import static


app_name = "djangoapp"

urlpatterns = [
    path("", views.index, name="index"),
    path("register/", views.register, name="register"),
    path("activate/<uidb64>/<token>/", views.activate, name="activate"),
    path("login/", auth_views.LoginView.as_view(template_name="djangoapp/login.html"), name="login"),
    path("logout/", auth_views.LogoutView.as_view(template_name="djangoapp/login.html"), name="logout"),
    path("reset-password/", auth_views.PasswordResetView.as_view(template_name="djangoapp/password_reset.html"), name="password-reset"),
    path("reset-password-confirm/<uidb64>/<token>/", views.ResetPasswordConfirm.as_view(), name="reset-password-confirm")
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)