import boto3
from email.headerregistry import Address
from email.message import EmailMessage
from flask import jsonify
from jinja2 import (
    Environment,
    select_autoescape,
    FileSystemLoader,
)
from typing import List

env = Environment(loader=FileSystemLoader("templates"), autoescape=select_autoescape())
client = boto3.client('sesv2', region_name="us-east-2")

def build_email(delivery: DeliveryDispatchOrder):
    email_message = EmailMessage()
    email_message["Subject"] = "New Order"
    email_message["From"] = Address(
        username="noresponse", domain="hensallco-op.ca", display_name="Hensall Co-op"
    )

    email_part = delivery.driver.email.split("@")
    email_message["To"] = Address(
        username=email_part[0], domain=email_part[1], display_name=delivery.driver.name
    )
    html_data: str = render_html(delivery)
    email_message.add_alternative(html_data, subtype="html")
    '''
    email_message.add_attachment(
        open_file_image(), maintype="image", subtype="png", filename="Wallpaper.png"
    )
    '''
    send_email(email_message=email_message, email="crangarita@gmail.com")


def send_email(email_message: EmailMessage, email):
    CHARSET = "UTF-8"

    response = client.send_email(
        FromEmailAddress="crangarita@gmail.com",
        Destination={
            "ToAddresses": [email],
        },
        Content={"Raw": {"Data": email_message.as_string()}},
    )
    resp = {
        'msg': 'Email sended'
    }
    return jsonify(resp)


def render_html(delivery: DeliveryDispatchOrder):

    template_result = env.get_template("welcome.html")
    template_result = template_result.render(delivery=delivery)
    return template_result
