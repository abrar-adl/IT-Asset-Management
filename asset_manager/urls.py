from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from assets import views as asset_views
from assets import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('assets.urls')),
    path('logout/', auth_views.LogoutView.as_view(next_page='/login/'), name='logout'),
    path('login/', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    path('password_reset/', auth_views.PasswordResetView.as_view(template_name='password_reset.html'), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='password_reset_confirm.html'), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'), name='password_reset_complete'),
    path('scan-history/', views.scan_history, name='scan_history'),

    # Register
    path('register/', asset_views.register, name='register'),

]