from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.contrib.sites.shortcuts import get_current_site
from django.contrib import messages
from django.contrib.auth import login as auth_login
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.views import PasswordResetView, PasswordResetConfirmView

from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

from django.shortcuts import render, redirect
from django.core.mail import EmailMessage, send_mail




account_activation_token = PasswordResetTokenGenerator()


def register(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")


        # Credential validation for registration

        if password != confirm_password:
            message = "Password not match!"
            return render(request, "djangoapp/register.html", {"message":message})
        
        if User.objects.filter(username=username).exists():
            message = "Username already exists!"
            return render(request, "djangoapp/register.html", {"message":message})
        
        if User.objects.filter(email=email).exists():
            message = "Email already exists!"
            return render(request, "djangoapp/register.html", {"message":message})
        


        # Create user if not exists

        user = User.objects.create(
            username=username,
            email=email,
            password=make_password(password)
        )
        user.is_active = False
        user.save()



        # Send activation email message

        current_site = get_current_site(request)
        mail_subject = "Activate Your Account"
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = account_activation_token.make_token(user)

        message = (
            f"Hi {user.username}, \n\n"
            "Thank you for signing up! Please click the link below to activate your account: \n"
            f"http://{current_site.domain}/activate/{uid}/{token}\n\n"
            "For reference, here are your activation details:\n"
            f"Email: {email}\n"
            f"Token: {token}\n"
            "If you did not sign up for this account, you can ignore this email.\n\n"
            "Best regards,\n"
            "DJdev"
        )


        email = EmailMessage(mail_subject, message, to=[email])
        email.send()

        messages.success(request, "Please check your email to complete your activation!")
        return redirect("djangoapp:login")
    
    return render(request, "djangoapp/register.html")



def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()


        auth_login(request, user)
        messages.success(request, "Your account has been successfully activated!")
        return redirect("djangoapp:index")
    else:
        # If the user is None or the token is invalid, return an error message
        messages.error(request, "Activation link is invalid!")
        return redirect("djangoapp:login") 


class ResetPassword(PasswordResetView):
    template_name = "djangoapp/reset_password.html"

    def send_email(self, subject_name, email_name, context, from_email, to_email, html_email_template_name=None):
        
        # Build plain text message

        user = context.get("username")
        domain = context.get("domain")
        uid = context.get("uid")
        token = context.get("token")
        
        message = (
            f"Hi {user.username},\n\n"
            "You requested to reset your password.Click the link below to reset it:\n\n"
            f"http://{domain}/reset/{uid}/{token}\n\n"
            "If you did not request a password reset, you can safely ignore this email.\n\n"
            "Best regards,\n"
            "DJdev"
        )

        send_mail(
            subject="Password Reset Request",
            message=message,
            from_email=from_email,
            recipient_list=[to_email],
            fail_silently=False,
        )

class ResetPasswordConfirm(PasswordResetConfirmView):
    template_name = "djangoapp/reset_password_confirm.html"



def index(request):
    return render(request, "djangoapp/home.html")

def login(request):
    return render(request, "djangoapp/login.html")