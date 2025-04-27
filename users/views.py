from rest_framework import generics
from .models import User
from .serializers import UserRegisterSerializer
from rest_framework.permissions import AllowAny

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = UserRegisterSerializer



from django.views.generic import TemplateView
from django.conf import settings
from django.contrib.auth import login, authenticate, logout
from rest_framework.views import APIView
from users.models import *
from django.http import JsonResponse, HttpResponseRedirect
from urllib.parse import urlparse
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from django.contrib.auth.models import User
from rest_framework import status
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt
from cryptography.fernet import Fernet
# from django.contrib.sites.models import Site

# from cryptography.fernet import Fernet
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView,TokenVerifyView,TokenBlacklistView
from rest_framework.response import Response
# from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework.views import APIView
import jwt
from django.contrib.auth.models import User
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from datetime import timedelta
from django.conf import settings
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from django.contrib.sessions.backends.db import SessionStore
from rest_framework.request import Request
from django.http import HttpRequest
import json
from rest_framework import status
from django.utils import timezone
from rest_framework_simplejwt.exceptions import TokenError
from cryptography.fernet import Fernet
from django.middleware.csrf import get_token


cipher_suite = Fernet('I4mV0gqvRs6YMFvB9VmcrPvnVDJdEefUGrImbNAqvU0=')
# secret_key = Fernet.generate_key()

# # Print the key or save it to a file (make sure to store it securely)
# print(secret_key.decode())
def encrypt_token(token: str) -> str:
    """Encrypt the token."""
    encrypted_token = cipher_suite.encrypt(token.encode())
    return encrypted_token.decode()

def decrypt_token(encrypted_token: str) -> str:
    """Decrypt the token."""
    decrypted_token = cipher_suite.decrypt(encrypted_token.encode())
    return decrypted_token.decode()

class RefreshTokenAPIView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        encrypted_access_token = request.data.get('access_token')
        encrypted_refresh_token = request.data.get("refresh_token")
        decrypted_access_token = cipher_suite.decrypt(encrypted_access_token.encode()).decode()
        decrypted_refresh_token = cipher_suite.decrypt(encrypted_refresh_token.encode()).decode()

        if not decrypted_refresh_token:
            return Response({"error": "Refresh token missing"}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            AccessToken(decrypted_access_token)
            return Response({"message": "Access token is valid"}, status=status.HTTP_200_OK)
        except Exception:
            pass
        
        try:
            refresh = RefreshToken(decrypted_refresh_token)
            access_token = str(refresh.access_token)
            encrypted_access_token = encrypt_token(access_token)
        except Exception:
            return Response({"error": "Invalid refresh token"}, status=status.HTTP_401_UNAUTHORIZED)

        response = Response({"message": "Token refreshed", "access_token":encrypted_access_token}, status=status.HTTP_200_OK)
        return response

class EncryptedJWTAuthentication(BaseAuthentication):
    """
    Custom authentication class that decrypts an encrypted JWT token,
    decodes it, and authenticates the user.
    """

    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith("Bearer "):
            return None

        encrypted_token = auth_header.split(" ")[1]

        # Decrypt the token
        token = decrypt_token(encrypted_token)
        if not token:
            raise AuthenticationFailed("Invalid or corrupted token")

        try:
            # Decode the JWT token
            decoded_data = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user_id = decoded_data.get("user_id")

            # Fetch user from database
            user = User.objects.get(id=user_id)
            return (user, None)  # Return user and authentication info

        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token has expired")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token")
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found")


class GetCSRFToken(APIView):
    authentication_classes = [EncryptedJWTAuthentication]
    def get(self, request):
        csrf_token = get_token(request)
        return Response({'csrf_token':csrf_token},status=status.HTTP_200_OK)








class AuthSigninView(TemplateView):
    template_name = 'users/login.html'

    def get_context_data(self, **kwargs):
        # Call the base implementation first to get a context
        context = super().get_context_data(**kwargs)

        # A function to init the global layout. It is defined in _keenthemes/__init__.py file
        
        context['next'] = self.request.GET.get('next', '/')

       

        # Define the layout for this module
        # _templates/layout/auth.html
        context.update({
            
            'current_user': self.request.user,
            'exclude_tokenCheck_js': True,
        })

        return context
    

class AuthSigninApiView(APIView):
    # def get_authenticators(self):
    #     return []
    @csrf_exempt
    def post(self, request):
        # self.clear_csrf_and_session(request)
        username = request.data.get('username')
        password = request.data.get('password')
        
        user = authenticate(request, username=username, password=password)

        if user is not None:
            
            
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            # Encrypt the tokens before sending in the response
            encrypted_access_token = encrypt_token(access_token)
            encrypted_refresh_token = encrypt_token(str(refresh))

            # Obtain the CSRF token
            # csrf_token = get_token(request)
           
            token = {
                'access_token':encrypted_access_token,
                'refresh_token':encrypted_refresh_token
            }
            
            return JsonResponse({'message': 'success', 'token':token}, status=status.HTTP_200_OK)
           
        else:
            try:
                existing_user = User.objects.get(username=username)
                if existing_user:
                    return JsonResponse({'message':'password is incorrect'}, status=status.HTTP_401_UNAUTHORIZED)
                
            except User.DoesNotExist:
                return JsonResponse({'message':'username is incorrect'}, status=status.HTTP_404_NOT_FOUND)

    # def clear_csrf_and_session(self, request):
    #     """
    #     Clears the CSRF token and session ID on successful login.
    #     """
    #     # Clear CSRF token (delete the CSRF cookie and token)
    #     response = JsonResponse({"data":"data"})
    #     response.delete_cookie('csrftoken')  # Delete CSRF cookie
    #     get_token(request)  # This will update the CSRF token

    #     # Clear session ID
    #     request.session.flush()  # This will clear the session and session ID

    #     return response

# Logout View
class LogoutAPIView(APIView):
    # permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request):
        encrypted_access_token = request.data.get('access_token')
        encrypted_refresh_token = request.data.get('refresh_token')

        try:
            decrypted_access_token = cipher_suite.decrypt(encrypted_access_token.encode()).decode()
            decrypted_refresh_token = cipher_suite.decrypt(encrypted_refresh_token.encode()).decode()
            
            # Blacklist Refresh Token
            try:
                refresh_token = RefreshToken(decrypted_refresh_token)
                refresh_token.blacklist()
            except:
                pass

            # Blacklist Access Token
            try:
                access_token = AccessToken(decrypted_access_token)
                access_token.blacklist()
            except Exception:
                pass
        except Exception as e:
            return JsonResponse({"message": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)
        return JsonResponse({"message": "Token Blacklisted"}, status=status.HTTP_200_OK)
    



