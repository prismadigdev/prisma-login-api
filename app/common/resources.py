import boto3
from flask import session

S3_BUCKET = "3energy-prod"

def _get_s3_resource():
    return boto3.resource('s3')

def get_bucket():
    s3_resource = _get_s3_resource()
    if 'bucket' in session:
        bucket = session['bucket']
    else:
        bucket = S3_BUCKET

    return s3_resource.Bucket(bucket)

def get_buckets_list():
    client = boto3.client('s3')
    return client.list_buckets().get('Buckets')