import mimetypes
import smtplib
import ssl
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class Messaging:

    def __init__(self, config_data: dict):
        self.cfg = config_data
        self.smtp_server = self.cfg['smtp']['server']
        self.port = self.cfg['smtp']['port']
        self.sender_email = self.cfg['smtp']['email']
        self.password = self.cfg['smtp']['password']
        self.dest_email = self.cfg['smtp']['destination_email']
        self.text_body = self.cfg['smtp']['body']
        self.send_cc = self.cfg['smtp']['destination_email_cc'] if self.cfg['smtp']['destination_email_cc'] else None

    def prep_message(self, attachment_name: str, msg_attachment_location):
        message = MIMEMultipart("alternative")
        message["Subject"] = f"{self.cfg['report']['Command_name']} C2C phase {self.cfg['ComplytoConnect']['phase']} Interim Report"
        message["From"] = self.sender_email
        message["To"] = self.dest_email
        if self.send_cc is not None:
            message["Cc"] = ', '.join(self.send_cc)

        # message body
        message.attach(MIMEText(self.text_body, 'plain'))
        # message attachment
        ctype, encoding = mimetypes.guess_type(msg_attachment_location)
        if ctype is None or encoding is not None:
            ctype = "application/octet-stream"
        maintype, subtype = ctype.split("/", 1)

        with open(msg_attachment_location, "rb") as fp:
            part = MIMEBase(maintype, subtype)
            part.set_payload(fp.read())

        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename={attachment_name}", )
        message.attach(part)
        return message

    def send_message(self, msg_attachment_location):
        if '/' in msg_attachment_location:
            attachment_name = msg_attachment_location.split('/')[-1]
        else:
            attachment_name = msg_attachment_location.split('\/')[-1]

        message = self.prep_message(attachment_name, msg_attachment_location)

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
        except Exception as e:
            print(e)
        finally:
            server.quit()
