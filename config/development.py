SECRET_KEY = '123447a47f563e90fe2db0f56b1b17be62378e31b7cfd3adc776c59ca4c75e2fc512c15f69bb38307d11d5d17a41a7936789'
PROPAGATE_EXCEPTIONS = True

# Database configuration
SQLALCHEMY_TRACK_MODIFICATIONS = False
SHOW_SQLALCHEMY_LOG_MESSAGES = False
ERROR_404_HELP = False

# Project configuration
PROJECT = "hlogin"
SITE_HOST = 'plogin-api.prismaqa.com'
FRONT_SITE_HOST = 'https://plogin.prismaqa.com/'

CORS = ["https://plogin.prismaqa.com", "http://localhost:3000","http://localhost:4200"]

# AWS configuration
AWS_PROFILE = "HensallEnergy"
AWS_DEFAULT_REGION = "us-east-1"

S3_BUCKET = "3energy-prod"
S3_LOCATION = "http://{}.s3.amazonaws.com/".format(S3_BUCKET)

AWS_BUCKET_NAME = "hensallfiles"
AWS_DOMAIN = "http://hensallfiles.s3.amazonaws.com/"

# AWS SES - SMTP
SMTP_HOST = "email-smtp.ca-central-1.amazonaws.com"
SMTP_FROM = "prod.hensall.ca@gmail.com"

SECURITY_ROLE = "YES"
SECURITY_IP = "NO"

#Keys
KEYZEROB = "db2dc24e5e9548d4ba1456f445a89a13"
USERPOOL = "us-east-1_zoId0epNt"
OL = "1qip37c38k0v9io2t86u1jat43"
RECAPTCHA = "6LcLNTAkAAAAAJVNjdJSgsoUM_TlSBn4WnWhBQZo"

# Para validación de token en consumo de aplicaciones de terceros
SUSCRIPTION_URL = "https://integration-api.prismaqa.com/api/v1/auth/login/"
SUSCRIPTIONNEW_URL = "https://integrationnew-api.prismaqa.com/api/v1/auth/validate"

# SAML CONFIGURATION
SAML_CONFIGURATION = "development"