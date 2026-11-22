from django.urls import path

from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('salud/', views.salud, name='salud'),
    path('historial/', views.historial, name='historial'),
    path('analizar/', views.analizar, name='analizar'),
    path('escanear/', views.escanear_puertos, name='escanear'),
    path('headers/', views.verificar_headers, name='headers'),
    path('analisis/<int:pk>/', views.detalle, name='detalle'),
    path('analisis/<int:pk>/pdf/', views.exportar_pdf, name='exportar_pdf'),
    path('analisis/<int:pk>/json/', views.exportar_json, name='exportar_json'),
    path('analisis/<int:pk>/eliminar/', views.eliminar, name='eliminar'),
]
