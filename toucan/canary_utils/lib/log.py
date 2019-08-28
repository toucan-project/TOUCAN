from time import sleep
from io import SEEK_END
from os import access, R_OK
from datetime import datetime
from calendar import month_abbr

from django.utils import timezone

from canary_files.models import CanaryItem
from alert_api.models import CanaryAlertItem


class Log():
    """Generic class for log parsing."""

    def monitor_log(self, parse_line, log, state):
        """Tail the log file for new lines."""

        if not access(log, R_OK):
            raise FileNotFoundError(f"Cannot access {log}")

        log = open(log, 'r')
        log.seek(0, SEEK_END)

        while state.is_active:

            line = log.readline()

            if line:
                parse_line(line)

            else:
                sleep(0.5)


class Nginx():
    """Monitoring class for finding Nginx canaries."""

    def parse(self, line):
        """Parse a line from the Nginx log."""

        # split the log date and the entry
        ls = line.split(' - - ')

        # if the split does not result in at least two parts the line is invalid
        if len(ls) < 2:
            return False

        # get data part, remote ip and node
        syslog_line = ls[0].split()

        # the syslog line should consist of no less than 4 items
        if len(syslog_line) < 4:
            return False

        node = syslog_line[3]
        rip = syslog_line[-1]

        # get the nginx line
        nginx_line = ls[1].split('"-"')

        if len(nginx_line) != 2:
            return False

        date, tz, method, uri, http, status, _ = nginx_line[0].split()

        filename = uri.split('/')[-1]

        # get the user-agent
        ua = nginx_line[1]

        # return a django aware date
        date = self._get_django_date(' '.join([date, tz]))
        method = method.replace('"', '')

        hit = ["200", "304"]

        if status in hit:
            self._find_canary_nginx(method, filename, date, rip, node, ua)

        return False

    def _find_canary_nginx(self, method, filename, date, ip, node, ua):
        """Find canary inside parsed line."""

        for item in CanaryItem.objects.filter(canary_filename=filename):
            if method == "GET":

                args = {'date': date, 'identifier': item.identifier,
                        'canary_type': 'http', 'location': item.location,
                        'ip': ip, 'node': node, 'filename': filename,
                        'user_agent': ua}

                CanaryAlertItem.create_object(**args)

    def _get_django_date(self, date):
        """Create aware Django date from log date."""

        pdate = date.split(']')[0].lstrip('[')
        ddate = pdate.split('/')

        day = ddate[0]
        month = self._get_month_number(ddate[1])
        year = ddate[2].split(':')[0]
        date = f"{year}-{month}-{day}"

        time = ':'.join(ddate[2].split()[0].split(':')[1:4])
        timedate = f"{date} {time} UTC"

        aware_date = timezone.make_aware(datetime.strptime(
                                         timedate,
                                         "%Y-%m-%d %H:%M:%S %Z"),
                                         timezone.get_default_timezone()
                                         )
        return aware_date

    def _get_month_number(self, name):
        """Get the number of the month."""

        for i, month in enumerate(month_abbr):

            if month == name:
                return i


class SMB():
    "Class for SMB log monitoring."""

    def parse(self, line):
        """Parse an SMB log line."""

        # split the date and the smb part
        ls = line.split("]:")

        # the smb log items are separated by |
        if len(ls[1].split('|')) < 4:
            return False

        # smb operation
        op = ls[1].split('|')[3]

        if op == 'open':
            # obtain the filename
            filename = ls[1].split('|')[6]

            # get the syslog node
            node = ls[0].split()[3]
            date = ' '.join(ls[0].split()[0:3])

            # get the smb user
            user = ls[1].split('|')[0][1::]

            # remote ip of the user
            rip = ls[1].split('|')[1]

            # smb location
            location = ls[1].split('|')[2]

            index = filename.find('\n')

            if index != -1:
                filename = filename[0:index]

            self._find_canary_smb(user, location, filename, rip, date, node)

        return False

    def _find_canary_smb(self, user, location, filename, ip, date, node):
        """Find canary in parsed log line."""

        for item in CanaryItem.objects.filter(canary_filename=filename):

            args = {'date': date, 'identifier': item.identifier,
                    'canary_type': 'smb_unc',
                    'location': item.location,
                    'ip': ip, 'node': node, 'smb_loc': location,
                    'filename': filename}

            CanaryAlertItem.create_object(**args)


class DNS():
    """Class for DNS log monitoring."""

    def parse(self, line):
        """Parse a DNS query log line."""

        if line.find('query') == -1:
            return False

        ls = line.split()

        node = ls[3]
        hostname = ls[-5]

        # split the source port from the ip
        rip = ls[-8].split('#')[0]

        self._find_canary_dns(hostname, rip, node)

        return True

    def _find_canary_dns(self, hostname, ip, cs):
        """Find DNS canary in parsed DNS line."""

        identifier = hostname.split('.')[0]

        for item in CanaryItem.objects.filter(identifier=identifier):

            args = {'date': timezone.now(), 'identifier': item.identifier,
                    'canary_type': 'dns', 'location': item.location,
                    'ip': ip, 'node': cs}

            CanaryAlertItem.create_object(**args)
