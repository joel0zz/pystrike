import boto3
import json
import base64


def get_secret(bucket_name, object_name, region):
    set_profile()
    encrypted_obj = get_obj_from_s3(bucket_name, object_name)
    secret = decrypt_object(encrypted_obj, region)
    return secret


def get_obj_from_s3(bucket, file):
    client = boto3.client('s3')
    obj = client.get_object(Bucket=bucket, Key=file)
    response = obj['Body'].read()
    return response


def decrypt_object(obj, region):
    client = boto3.client('kms', region_name=region)
    binary_data = base64.b64decode(obj)
    meta = client.decrypt(CiphertextBlob=binary_data)
    plaintext = meta[u'Plaintext']
    secret_dict = json.loads(plaintext.decode())
    return secret_dict


def set_profile():
     boto3.setup_default_session(profile_name='credential_manager')