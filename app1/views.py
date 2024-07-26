from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.urls import reverse

@login_required(login_url='login')
def HomePage(request):
    user = request.user  # Get the current authenticated user
    context = {
        'username': user.username.upper(),
        'email': user.email,
    }
    return render(request, 'home.html', context)

def SignupPage(request):
    if request.method == 'POST':
        uname = request.POST.get('username')
        email = request.POST.get('email')
        pass1 = request.POST.get('password1')
        pass2 = request.POST.get('password2')

        if not uname or not email or not pass1 or not pass2:
            messages.error(request, '*All fields are required.')
            return redirect('signup')
        
        if User.objects.filter(username=uname).exists():
            messages.error(request, '*Username already exists.')
            return redirect('signup')

        if pass1 != pass2:
            messages.error(request, "*Passwords must be same")
            return redirect("signup")
          
        else:
            my_user = User.objects.create_user(uname, email, pass1)
            my_user.save()
            
            print(uname, " ", email, " ", pass1, " ", pass2)
            
            messages.success(request, 'User has been created successfully.', extra_tags='success')

    return render(request, 'signup.html')

def LoginPage(request):
    if request.method == 'POST':
        uname = request.POST.get('username')
        pass1 = request.POST.get('pass')
        user = authenticate(request, username=uname, password=pass1)

        if not uname or not pass1:
            messages.error(request, 'Please fill in all fields.')
            return redirect('login')
            
        else:
            if user is not None:
                login(request, user)
                return redirect('home')
            else:
                messages.error(request, 'Invalid details')
                return redirect('login')

    return render(request, 'login.html')

def LogoutPage(request):
    logout(request)
    return redirect('login')

def ForgotPasswordPage(request):
    if request.method == 'POST':
        uname = request.POST.get('username')
        email = request.POST.get('email')
        try:
            user = User.objects.get(username=uname, email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            reset_link = request.build_absolute_uri(reverse('reset_password', kwargs={'uidb64': uid, 'token': token}))
            context = {'reset_link': reset_link}
            return render(request, 'forgot_password.html', context)
        except User.DoesNotExist:
            messages.error(request, 'Username and email do not match any account')
            return redirect('forgot_password')
    return render(request, 'forgot_password.html')

def ResetPasswordPage(request, uidb64, token):
    if request.method == 'POST':
        pass1 = request.POST.get('password1')
        pass2 = request.POST.get('password2')
        if pass1 != pass2:
            messages.error(request, "Passwords do not match")
            return redirect(request.path)
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            if default_token_generator.check_token(user, token):
                user.set_password(pass1)
                user.save()
                messages.success(request, "Password reset successfully")
                return redirect('login')
            else:
                messages.error(request, "Invalid token")
                return redirect('forgot_password')
        except User.DoesNotExist:
            messages.error(request, "Invalid user")
            return redirect('forgot_password')
    return render(request, 'reset_password.html')
