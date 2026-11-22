from django.contrib import admin
from django.contrib.auth.views import LogoutView
from django.urls import path, include

from scanner.views import LoginConLimite

urlpatterns = [
    path('admin/', admin.site.urls),
    path('cuentas/login/', LoginConLimite.as_view(), name='login'),
    path('cuentas/logout/', LogoutView.as_view(), name='logout'),
    path('', include('scanner.urls')),
]
