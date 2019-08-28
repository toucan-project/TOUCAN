from django.urls import reverse
from django.conf.urls import url
from django.contrib import admin
from manage_api.admin import admin_site
from django.utils.html import format_html

from canary_files.models import CanaryItem, Deployment


class CanaryItemAdmin(admin.ModelAdmin):

    fields = ['identifier', 'trigger_type', 'location',  'added_by', 'dns',
              'protocol', 'domain', 'canary_filename', 'filename',
              'related_alert_items']
    list_display = ['identifier', 'trigger_type', 'added_by']
    list_filter = ['identifier', 'added_by']

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return True

    def has_change_permission(self, request, obj=None):
        return False

    def related_alert_items(self, obj):

        related = CanaryItem.get_related_alert_items(obj)

        if not related:
            return "N/A"

        return format_html(related)


class DeploymentAdmin(admin.ModelAdmin):

    list_display = ['canary', 'state', 'canary_string']
    fields = ['date', 'canary', 'canary_string', 'dest', 'state', 'reason',
              'redeploy_action']
    readonly_fields = ['redeploy_action', 'date', 'canary', 'canary_string',
                       'dest', 'reason']
    list_filter = ['canary', 'state']

    def has_add_permission(self, request, obj=None):
        return False

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            url(
                r'^(?P<canary>.+)/trigger/$',
                self.admin_site.admin_view(self.redeploy),
                name='redeploy',
            ),
        ]
        return custom_urls + urls

    def redeploy(self, request, *args, **kwargs):
        return self.deploy_action(request, **kwargs)

    def redeploy_action(self, canary):

        if canary.state == 'failed':

            return format_html(
                '<a class="button" href="{}">Redeploy</a>',
                reverse('admin:redeploy', args=[canary]),
            )

        else:
            return 'N/A'

    def deploy_action(self, request, canary):
        canary = CanaryItem.objects.get(identifier=canary)
        canary.redeploy_remote_files()

        return admin.ModelAdmin.response_change(self, request, canary)


admin_site.register(Deployment, DeploymentAdmin)
admin_site.register(CanaryItem, CanaryItemAdmin)
