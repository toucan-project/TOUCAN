"""canaryAPI URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path
from django.conf.urls import url, include

from rest_framework.permissions import IsAuthenticated
from rest_framework.documentation import include_docs_urls

from manage_api.admin import admin_site
from manage_api.views import AddExternalAPISetting
from manage_api.views import TriggerItem, DownloadItem
from manage_api.views import SysmonAlertItems, UserItem, UserItems
from canary_log_api.views import ViewLog

from canary_files.views import GenerateCanaryItem, DownloadCanaryItem

from alert_api.views import CanaryAlertItems, SysmonIncoming, FileItem


managepatterns = [
    path('', UserItem.as_view(), name='user_item'),
    path('users/', UserItems.as_view(), name='user_items'),
    path('sysmon/', SysmonAlertItems.as_view(), name='sysmon_alert_items'),
    path('sysmon/<int:id>', SysmonAlertItems.as_view(),
         name='sysmon_alert_item'),
    path('trigger/', TriggerItem.as_view(), name='trigger_item'),
    path('trigger/<int:id>', TriggerItem.as_view(), name='trigger_item'),
    path('api_settings/', AddExternalAPISetting.as_view(), name='external-setting'),
    path(r'download/<md5>', DownloadItem.as_view(), name='download-sample'),
]

apipatterns = [
    path('alert/', SysmonIncoming.as_view(), name='incoming-mimialert'),
    path('alert/log/', CanaryAlertItems.as_view()),
    path('alert/log/<int:id>', CanaryAlertItems.as_view(), name='triggered-alerts'),
    path('alert/upload/<str:filename>/', FileItem.as_view(), name='incoming-sample'),
    path('manage/', include(managepatterns)),
    path('canary/', GenerateCanaryItem.as_view(), name='canary'),
    path('log/', ViewLog.as_view(), name='logs'),
    path('canary/download/<identifier>', DownloadCanaryItem.as_view(),
         name='download-canary'),
]

urlpatterns = [
    path('admin/', admin_site.urls),
    path('api/', include(apipatterns)),
    path('api-docs/', include_docs_urls(title='Canary API', public=False, permission_classes=[IsAuthenticated])),
    url(r'^api-auth/', include('rest_framework.urls')),
]
