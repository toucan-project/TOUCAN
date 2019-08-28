from django.contrib import admin

from scheduler.models import CronJob, RepeatableJob, ScheduledJob

from canary_files.models import Deployment
from canary_log_api.models import CanaryLogItem

from manage_api.models import User
from manage_api.models import ExternalAPISetting, Trigger
from manage_api.models import DefaultSetting, SMSSetting, SMTPSetting


class CanaryAdminSite(admin.AdminSite):
    site_header = 'Toucan'

    def index(self, request, extra_context=None):
        extra_context = {}
        deployments = Deployment.objects.filter(state='failed')
        extra_context['failed_deployments'] = {'count': deployments.count()}

        ssl_warnings = CanaryLogItem.objects.filter(
                                msg__startswith='[SSL WARNING]'
                            )
        extra_context['ssl_warnings'] = {'count': ssl_warnings.count()}

        return super(CanaryAdminSite, self).index(request,
                                                  extra_context=extra_context)

    def has_module_permission(self, request):
        return True

    def has_permission(self, request):
        user = request.user
        return user.is_active and user.is_staff


admin_site = CanaryAdminSite(name='canaryadmin')


class UserAdmin(admin.ModelAdmin):

    search_fields = ['username']

    exclude = ['password', 'groups', 'first_name', 'last_name']
    list_display = ['username', 'email', 'phonenumber', 'last_login']

    fields = ['username', 'email', 'phonenumber', 'api_token',
              'is_superuser', 'is_staff', 'is_active',
              'last_login', 'date_joined']
    readonly_fields = ['date_joined', 'last_login', 'api_token']


class ExternalAPISettingAdmin(admin.ModelAdmin):
    list_display = ['api_name']


class TriggerAdmin(admin.ModelAdmin):

    list_display = ['canary', 'mimialert',  'email', 'sms']
    readonly_fields = ['date']
    exclude = ['trigger_identifier']


class DefaultSettingAdmin(admin.ModelAdmin):
    list_display = ['setting_name', 'domain_name', 'protocol', 'dns']


class SMSSettingAdmin(admin.ModelAdmin):
    list_display = ['sms_server', 'sms_endpoint']


class SMTPSettingAdmin(admin.ModelAdmin):
    list_display = ['smtp_server', 'smtp_port', 'ssl']


class FailedDeploymentAdmin(admin.ModelAdmin):
    list_display = ['date', 'msg', 'identifier', 'count']
    readonly_fields = ['redeploy_action']

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return True

    def has_change_permission(self, request, obj=None):
        return False


admin_site.register(CronJob)
admin_site.register(ScheduledJob)
admin_site.register(RepeatableJob)
admin_site.register(User, UserAdmin)
admin_site.register(Trigger, TriggerAdmin)
admin_site.register(SMSSetting, SMSSettingAdmin)
admin_site.register(SMTPSetting, SMTPSettingAdmin)
admin_site.register(DefaultSetting, DefaultSettingAdmin)
admin_site.register(ExternalAPISetting, ExternalAPISettingAdmin)
