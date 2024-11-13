from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from .forms import SignUpForm
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.models import User
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.sites.models import Site
from django.template.loader import render_to_string
from django.utils.http import base36_to_int
from django.contrib.auth import get_user_model
from django.utils.html import strip_tags


def login_page(request):
    if request.method == 'POST':
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            return HttpResponse("No User Found")
    else:
        return render(request, 'login_page.html')

@login_required
def dashboard(request):
    return render(request, 'dashboard_page.html', {'username': request.user.username})

@login_required
def profile(request):
    user = request.user
    return render(request, 'profile_page.html', {
        'username': user.username,
        'email': user.email,
        'date_joined': user.date_joined,
        'last_login': user.last_login
    })

def logout_view(request):
    logout(request)
    return redirect('login_page')

@login_required
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            form.save()
            update_session_auth_hash(request, form.user)
            return redirect('dashboard')
        else:
            return render(request, 'change_password_page.html', {'form': form})
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'change_password_page.html', {'form': form})

def signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login_page')
        else:
            return render(request, 'signup_page.html', {'form': form})
    else:
        form = SignUpForm()
    return render(request, 'signup_page.html', {'form': form})


def forgot_password(request):
    if request.method == 'POST':
        email = request.POST['email']
        user = User.objects.filter(email=email).first()

        if user:
            # Generate reset link
            token = default_token_generator.make_token(user)
            uidb64 = urlsafe_base64_encode(str(user.pk).encode())

            # Build the reset URL
            reset_url = f"{request.scheme}://{get_current_site(request).domain}/reset-password/{uidb64}/{token}/"

            # Send email
            subject = "Password Reset Request"
            message = render_to_string('password_reset_email.html', {
                'user': user,
                'reset_url': reset_url,
            })
            send_mail(subject, message, 'webmaster@localhost', [user.email])

        # Return a success message (you can improve this)
        return render(request, 'forgot_password.html', {'message': 'Check your email for the password reset link.'})
    
    return render(request, 'forgot_password.html')


def reset_password(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = get_user_model().objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = SetPasswordForm(user, request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, 'Your password has been reset successfully.')
                return redirect('login')
        else:
            form = SetPasswordForm(user)
        
        return render(request, 'reset_password.html', {'form': form})
    
    else:
        messages.error(request, 'The password reset link is invalid or has expired.')
        return redirect('login')
     