from smtplib import SMTP as smtp
from email.mime.text import MIMEText

from canary_log_api.models import CanaryLogItem
from manage_api.models import Trigger, SMTPSetting


class SMTP():
    """Class responsible for sending SMTP messages (email)."""

    def __init__(self):
        """Initialize class with settings from configuration."""

        self.settings = SMTPSetting.objects.get()

    def _construct_msg(self, date, identifier, ctype, location, ip,
                       ua, user, loc, cs, filename):
        """Construct email message."""

        msg = ("CANARY %s DIED\n"
               "Time:       %s\n"
               "Node:       %s\n"
               "Location:   %s\n"
               "Type:       %s\n"
               "IP addr :   %s\n" % (identifier.upper(), date, cs, location,
                                     ctype, ip))

        if ua:
            msg += "User-Agent: %s\n" % ua

        if user:
            msg += "SMB_user:   %s\n" % user

        if loc:
            msg += "SMB_share:  %s\n" % loc

        if filename:
            msg += "Filename:   %s\n" % filename

        msg = MIMEText(msg, 'plain')
        subject = "%s: %s died at %s [%s]" % (self.settings.subject,
                                              identifier, ctype,
                                              location)

        msg['Subject'] = subject
        msg['From'] = self.settings.sender

        recv = set()

        emails = Trigger.get_trigger_items_for_identifier(identifier)

        if emails:
            emails = emails.email

        if emails:
            emails.add(self.settings.default_recv)

        else:
            emails = set()
            emails.add(self.settings.default_recv)

        msg['To'] = ','.join(emails)

        return msg

    def send_mail(self, date, identifier, ctype, location, ip, cs,
                  ua=None, user=None, loc=None, filename=None):
        """Send email message."""

        try:

            s = smtp(self.settings.smtp_server, self.settings.smtp_port)
            s.ehlo()

            msg = self._construct_msg(date, identifier, ctype, location,
                                      ip, ua, user, loc, cs, filename)

            recv = recv if 'recv' in locals() else self.settings.default_recv
            s.sendmail(f"{self.settings.sender}", recv,
                       msg.as_string())

        except Exception as e:
            CanaryLogItem.log_message_id(None, identifier, e)
