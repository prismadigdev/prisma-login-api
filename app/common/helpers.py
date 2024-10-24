import boto3
import botocore
import os
from werkzeug.utils import secure_filename

aws_bucket_name = "hensallfiles"
s3 = boto3.client("s3")

def upload_file_to_s3(file, acl="public-read"):
    filename = secure_filename(file.filename)
    try:
        print(aws_bucket_name)

        s3.put_object(Body=file,
                          Bucket=aws_bucket_name,
                          Key="1_"+file.filename,
                          ContentType=file.content_type)

    except Exception as e:
        # This is a catch all exception, edit this part to fit your needs.
        print("Something Happened: ", e)
        return e

    # after upload file to s3 bucket, return filename of the uploaded file
    return file.filename


def s3_read_objects(s3_bucket_name, inp_file_key):
    read_object_response = s3.put_object(Bucket=aws_bucket_name, Key=inp_file_key)
    return read_object_response
