import os
import smtplib
from email.mime.text import MIMEText

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS", "check@scamwatcher.com.au")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD") or os.getenv("EMAIL_APP_PASSWORD")


def send_email(to_address, subject, body):
    if not EMAIL_ADDRESS:
        raise ValueError("EMAIL_ADDRESS is not configured")

    if not EMAIL_PASSWORD:
        raise ValueError("EMAIL_PASSWORD / EMAIL_APP_PASSWORD is not configured")

    if not to_address:
        raise ValueError("Recipient email address is missing")

    msg = MIMEText(body or "")
    msg["Subject"] = subject or ""
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_address

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)