import emails
import os
from app.customers.models.delivery_dispatch_order import DeliveryDispatchOrder
from flask import jsonify
from jinja2 import (
    Environment,
    select_autoescape,
    FileSystemLoader,
)

from app.common.email import render_html

SMTP_KEY = os.environ['SMTP_KEY']
SMTP_SECRET = os.environ['SMTP_SECRET']
SMTP_HOST = os.environ['SMTP_HOST']
SMTP_FROM = os.environ['SMTP_FROM']

env = Environment(loader=FileSystemLoader("templates"), autoescape=select_autoescape())


def build_email_smtp(delivery: DeliveryDispatchOrder):
    email_message = dict()
    email_message["Subject"] = "New Order"
    email_message["From"] = SMTP_FROM

    email_to = delivery.driver.email
    email_to = "crangarita@gmail.com"

    email_message["To"] = email_to

    html_data = render_html(delivery)

    email_message["Message"] = html_data

    send_email_smtp(email_message=email_message)


def send_email_smtp(email_message):
    CHARSET = "UTF-8"
    message = emails.html(
        html=email_message["Message"],
        subject=email_message["Subject"],
        mail_from=SMTP_FROM,
    )

    # Now you can send the email!
    r = message.send(
        to=email_message["To"],
        smtp={
            "host": SMTP_HOST,
            "port": 587,
            "timeout": 5,
            "user": SMTP_KEY,
            "password": SMTP_SECRET,
            "tls": True,
        },
    )

    resp = {
        'msg': 'Email sended' + email_message["Subject"]
    }
    return jsonify(resp)

