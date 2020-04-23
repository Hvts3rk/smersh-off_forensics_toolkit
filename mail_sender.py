import smtplib
from datetime import datetime
import os

def notify_service(intervallo, ip, labels):

    folder = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Documents') + "\\smersh_mail_setting.txt"
    with open(folder, mode="r") as file:
        content = file.read().split("|")

    now = datetime.now()
    timestamp = now.strftime("%d/%m/%Y %H:%M:%S")

    sender = content[0]
    receivers = content[1].split(',')
    message_payload = content[2].format(str(intervallo),", ".join(ip), ", ".join(labels), timestamp)
    address = content[3]

    try:
        smtpObj = smtplib.SMTP(address)
        smtpObj.sendmail(sender, receivers, message_payload)
        print "\n   [***] Notificate figure interessate!"
    except smtplib.SMTPException:
        print "\n[!] Error: unable to send email"

    return None

'''if __name__ == "__main__":
    notify_service(5, ["1","2"])'''