from django.contrib import admin

from manage_api.admin import admin_site

from canary_log_api.models import CanaryLogItem


class CanaryLogItemAdmin(admin.ModelAdmin):

    readonly_fields = ['date', 'user', 'canary', 'msg',
                       'stacktrace']
    list_display = ['date', 'msg', 'canary', 'user']
    search_fields = ['msg']

    def has_add_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False


admin_site.register(CanaryLogItem, CanaryLogItemAdmin)
