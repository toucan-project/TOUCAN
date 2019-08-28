from json import loads
from requests import Session

from canary_log_api.models import CanaryLogItem
from manage_api.models import Trigger, SMSSetting


class SMS():
    """Class responsible for sending SMS messages."""

    def __init__(self):
        """Initialize class with settings for sending SMS messages."""

        self.settings = SMSSetting.objects.get()

    def send_sms(self, identifier, date, location, ctype, ip):
        """Send an SMS message to target phone number."""

        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'X-Dynamic-Settings': 'authz.enabled'}

        session = Session()

        try:
            session, token = self._get_token(session, headers)

            msg = f"CANARY {identifier.upper()} DIED!"
            msg += f"{date}: {location}\n"
            msg += f"{ip} {ctype}"

            self._send_sms_request(session, headers, token, msg, identifier)

        except Exception as e:
            CanaryLogItem.log_message_id(None, identifier, e)

    def _get_token(self, session, headers):
        """Get token required for authenticating with the SMS server."""

        data = {'client_id': self.settings.sms_client,
                'client_secret': self.settings.sms_secret}

        response = session.post(url=f"https://{self.settings.sms_server}",
                                data=data, headers=headers)

        if response.status_code == 200:
            token = loads(response.text)['access_token']

        else:
            raise TypeError(f"cannot obtain token: "
                            f"received {response.status_code} != 200: "
                            f"{response.text}")

        return(session, token)

    def _send_sms_request(self, session, headers, token, text, identifier):
        """Send SMS message to targets as defined in the triggers."""

        url = self.settings.sms_endpoint

        messages = []

        numbers = Trigger.get_trigger_items_for_identifier(identifier)

        if not numbers:
            return False

        for number in numbers.sms:
            msg = {'mobile_number': number,
                   'content': text}
            messages.append(msg)

        data = {'messages': messages, 'sender': 'CERT-CANARY'}

        headers['Content-Type'] = 'application/json'
        headers['X-Authorization'] = f"Bearer {token}"
        headers.pop('X-Dynamic-Settings')

        response = session.post(url=f"https://{url}",
                                json=data, headers=headers)

        if response.status_code == 200:
            return response

        else:
            raise TypeError(f"Could not send SMS "
                            f"received {response.status_code} != 200: "
                            f"{response.text}")
