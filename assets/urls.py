from django.urls import path
from . import views
from .reports import export_json_report
from django.contrib.auth import views as auth_views
from assets.views import CustomLoginView

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('scan/', views.run_scan, name='run_scan'),
    path('risk/', views.risk_dashboard, name='risk_dashboard'),
    path('reports/', views.reports, name='reports'),
    path('export/', export_json_report, name='export_json'),
    path('lifecycle/', views.lifecycle_dashboard, name='lifecycle_dashboard'),
    path('logout/', auth_views.LogoutView.as_view(next_page='/'), name='logout'),    
    path('login/', CustomLoginView.as_view(), name='login'),
    # path('password_reset/', auth_views.PasswordResetView.as_view(template_name='password_reset.html'), name='password_reset'),
    # path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='password_reset_done.html'), name='password_reset_done'),
    # path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='password_reset_confirm.html'), name='password_reset_confirm'),
    # path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'), name='password_reset_complete'),
    # path('register/', views.register, name='register'),
    path('run-risk-scan/', views.run_risk_scan, name='run_risk_scan'),

]