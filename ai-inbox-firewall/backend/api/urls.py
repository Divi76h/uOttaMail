from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from . import views

urlpatterns = [
    path('auth/register/', views.register, name='register'),
    path('auth/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('emails/', views.emails, name='emails'),
    path('emails/<int:email_id>/', views.email_detail, name='email_detail'),

    path('events/stream/', views.event_stream, name='event_stream'),
]
