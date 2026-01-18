from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from . import views

urlpatterns = [
    path('auth/register/', views.register, name='register'),
    path('auth/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('emails/', views.emails, name='emails'),
    path('emails/<int:email_id>/', views.email_detail, name='email_detail'),

    path('action-items/', views.action_items, name='action_items'),
    path('action-items/<int:email_id>/<int:item_index>/toggle/', views.action_item_toggle, name='action_item_toggle'),

    path('search/', views.search_emails, name='search_emails'),
    path('chat/', views.chat_query, name='chat_query'),

    path('events/stream/', views.event_stream, name='event_stream'),
]
