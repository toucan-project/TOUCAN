from django.urls import reverse
from django.http import Http404
from django.conf.urls import url
from django.contrib import admin
from django.utils.html import format_html
from django.shortcuts import render_to_response

from requests import post

from manage_api.admin import admin_site
from manage_api.models import ExternalAPISetting

from alert_api.models import MimiAlertItem, SampleItem, CanaryAlertItem


class MimiAlertItemAdmin(admin.ModelAdmin):

    readonly_fields = ["target", "source", "stack", "accessMask",
                       "sha1", "md5", "date", "pid", "sid", "machinename",
                       "virustotal_actions"]
    list_display = ['date', 'machinename', 'target', 'source']
    list_filter = ['machinename', 'source']

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            url(
                r'^(?P<md5>.+)/check/$',
                self.admin_site.admin_view(self.process_md5),
                name='process-md5',
            ),
            url(
                r'^(?P<sha1>.+)/check/$',
                self.admin_site.admin_view(self.process_sha1),
                name='process-sha1',
            ),
        ]
        return custom_urls + urls

    def process_md5(self, request, md5, *args, **kwargs):
        return self.process_action(
            request=request,
            hash=md5,
            action_title='MD5',
        )

    def process_sha1(self, request, sha1, *args, **kwargs):
        return self.process_action(
            request=request,
            hash=sha1,
            action_title='SHA1',
        )

    def virustotal_actions(self, obj):
        return format_html(
            '<a class="button" href="{}">MD5</a>&nbsp;'
            '<a class="button" href="{}">SHA1</a>',
            reverse('admin:process-md5', args=[obj.md5]),
            reverse('admin:process-sha1', args=[obj.sha1]),
        )

    def process_action(self, request, hash, action_title):

        args = {}
        args.update(request)

        item = ExternalAPISetting.get_api_item_by_name('virustotal')
        vt_key = item.api_key

        params = {'apikey': vt_key, 'resource': hash}
        response = post('https://www.virustotal.com/vtapi/v2/file/rescan',
                        params=params)

        if response.status_code != 200:
            raise Http404('Could not obtain report, invalid response '
                          'from remote site.')

        response = response.json()
        report = response.get('permalink', False)

        if not report:
            raise Http404({'error': f"no report for {hash}"})

        response = post('https://www.virustotal.com/vtapi/v2/file/report',
                        params=params)

        # Sort dictionary by value: True
        response_dict = sorted(response.json()['scans'].items(),
                               key=lambda x: x[1]['detected'], reverse=True)
        args['contents'] = response_dict
        args['hash'] = hash
        args['report'] = report

        return render_to_response('virustotal_report_template.html', args)


class SampleItemAdmin(admin.ModelAdmin):

    list_display = ['md5', 'related_alert_items']
    fields = ['md5', 'related_alert_items', 'download_sample']

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return True

    def has_change_permission(self, request, obj=None):
        return False

    def related_alert_items(self, obj):
        items = SampleItem.get_related_alert_items_as_url(obj.md5)
        return format_html(items)

    def download_sample(self, obj):
        return format_html(
            '<a class="button" href="{}">Sample</a>',
            reverse('download-sample', args=[obj.md5]))


class CanaryAlertItemAdmin(admin.ModelAdmin):

    list_display = ['date', 'identifier', 'canary_type', 'location']
    list_filter = ['identifier']

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return True

    def has_change_permission(self, request, obj=None):
        return False


admin_site.register(SampleItem, SampleItemAdmin)
admin_site.register(MimiAlertItem, MimiAlertItemAdmin)
admin_site.register(CanaryAlertItem, CanaryAlertItemAdmin)
