import mimetypes
import smtplib
import ssl
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from utilities import Rutils, log_collector


class Messaging:
    UTILS = Rutils()

    def __init__(self, config_data: dict):
        self.cfg = config_data
        self.smtp_server = self.cfg['smtp']['server']
        self.port = self.cfg['smtp']['port']
        self.sender_email = self.cfg['smtp']['email']
        self.password = self.cfg['smtp']['password']
        self.dest_email = self.cfg['smtp']['destination_email']
        self.text_body = self.cfg['smtp']['body']
        self.send_cc = self.cfg['smtp']['destination_email_cc'] if self.cfg['smtp']['destination_email_cc'] else None
        self.logger = log_collector()

    def prep_message(self, attachment_name: str, msg_attac_loc_or_buf):
        message = MIMEMultipart("alternative")
        # if we need to use a alt name
        if not self.cfg.get('special_reporting').get('use'):
            message["Subject"] = f"{self.cfg['report']['Command_name']} C2C step {self.cfg['ComplytoConnect']['phase']} Interim Report"
        else:
            message["Subject"] = self.cfg['smtp']['alt_subject']
        message["From"] = self.sender_email
        message["To"] = self.dest_email
        if self.send_cc is not None:
            message["Cc"] = ', '.join(self.send_cc)

        # message body
        message.attach(MIMEText(self.text_body, 'plain'))
        # message attachment
        try:
            ctype, encoding = mimetypes.guess_type(msg_attac_loc_or_buf)
            if ctype is None or encoding is not None:
                ctype = "application/octet-stream"
            maintype, subtype = ctype.split("/", 1)

            with open(msg_attac_loc_or_buf, "rb") as fp:
                part = MIMEBase(maintype, subtype)
                part.set_payload(fp.read())
        except Exception as error:
            self.logger.debug(f'ISE_MESSAGING: {error}')
            part = MIMEApplication(self.UTILS.df_to_string_buffer(msg_attac_loc_or_buf))

        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename={attachment_name}", )
        message.attach(part)
        return message

    def send_message(self, msg_attac_loc_or_buf, attachment_name=None):
        if not attachment_name:
            if '/' in msg_attac_loc_or_buf:
                attachment_name = msg_attac_loc_or_buf.split('/')[-1]
            else:
                attachment_name = msg_attac_loc_or_buf.split('\/')[-1]
        else:
            attachment_name = attachment_name

        # Test case
        if self.cfg.get('test_messaging_svc'):
            message = self.test_prep_message()
        else:
            message = self.prep_message(attachment_name, msg_attac_loc_or_buf)

        if self.cfg['smtp']['port'] == 587:
            # Create a secure SSL context
            context = ssl._create_unverified_context()
        else:
            context = None

        # Try to log in to server and send email
        try:
            server = smtplib.SMTP(self.smtp_server, self.port)
            # SMTP-TLS         
            if context is not None:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()

            if self.password:
                server.login(self.sender_email, self.password)

            server.send_message(message)
            server.quit()
        except Exception as e:
            print(e)

    def test_prep_message(self):
        message = MIMEMultipart("alternative")
        message["Subject"] = f"{self.cfg['report']['Command_name']} C2C Phase {self.cfg['ComplytoConnect']['phase']} Report"
        message["From"] = self.sender_email
        message["To"] = self.dest_email
        if self.send_cc is not None:
            message["Cc"] = ', '.join(self.send_cc)

        # message body
        message.attach(MIMEText(self.text_body, 'plain'))
        return message
