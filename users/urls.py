from django.urls import path
from .views import *

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login',AuthSigninView.as_view(),name='login'),
    path('api/signin',AuthSigninApiView.as_view(),name='signin'),
    path('get-csrf', GetCSRFToken.as_view(),name="get-csrf")
]