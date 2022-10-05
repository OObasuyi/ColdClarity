from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests

import ise_control
import messaging

requests.packages.urllib3.disable_warnings()


class ISETest(ise_control.ISE):

    def __init__(self, config: str = "config.yaml", count_amt=50):
        super().__init__(config)
        self.count_amt = count_amt

    def retrieve_endpoint_data(self):
        # deployment ID
        self.sn = self.get_license_info()
        self.endpoint_policies = None
        self.logger.info('Collecting endpoint data, depending on size of database this can take some time')
        self.get_all_endpoint_data()
        # GET ONLY FIRST N
        self.endpoints = self.endpoints.loc[:self.count_amt]
        self.get_specific_metadata_from_endpoints()
        self.logger.info('Endpoint data collection complete')


class MessagingTest(messaging.Messaging):

    def __init__(self, config_data: dict):
        super().__init__(config_data)

    def prep_message(self, attachment_name=None, msg_attachment_location=None):
        message = MIMEMultipart("alternative")
        message["Subject"] = f"{self.cfg['report']['Command_name']} C2C Phase {self.cfg['ComplytoConnect']['phase']} Report"
        message["From"] = self.sender_email
        message["To"] = self.dest_email
        if self.send_cc is not None:
            message["Cc"] = ', '.join(self.send_cc)

        # message body
        message.attach(MIMEText(self.text_body, 'plain'))
        return message
