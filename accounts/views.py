
from django.contrib.auth.models import User
from django.contrib.auth import login,logout,authenticate
from rest_framework.response import Response


# Create your views here.
def register(request):
    username = request.data['username']
    password = request.data['password']

    user=User.object.createUser(
        username = username,
        password = password
    )

    login(request, user)

    return Response({"messages": "User created Successfully"})

def login_user(request):

    username = request.data['username'],
    password = request.data['password']

    user = authenticate(username, password)

    if user is None:
        return Response({"message": "Invalid Credentials"}, status = 404)
    
    login(request,user)
    return Response({"message": "User LoggedIn"})

def logout_user(request):
    logout(request)
    return Response({"message": "User Logged Out succesfully"})

