"""
Lambda function that receives an S3 event for a cloudtrail log file
Downloads the file from the event, insert its json contents into elasticsearch
Profit!

Signed URL code taken from AWS docs and adapted for this script
http://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html

Requires an access key with XXX permissions

Script will create an index for each day in the format
logstash-YYYY.MM.DD
with type cloudtrail
"""

import json
import gzip
import requests
import datetime
import hashlib
import hmac
import boto3
import os

########################################################################################################################
# variables to be changed

# no https nor trailing slash in this one, just the full hostname of your elasticsearch endpoint
host = 'Elasticsearch EndPoint'
region = 'us-east-1'
########################################################################################################################
access_key = os.environ.get('AWS_ACCESS_KEY_ID')
secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
session_token = os.environ.get('AWS_SESSION_TOKEN')
# variables that you should'nt have to change, ever :)
method = 'POST'
service = 'es'
content_type = 'application/x-amz-json-1.0'


# functions used in the aws signed url
def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def get_signature_key(key, date_stamp, region_name, service_name):
    k_date = sign(('AWS4' + key).encode('utf-8'), date_stamp)
    k_region = sign(k_date, region_name)
    k_service = sign(k_region, service_name)
    k_signing = sign(k_service, 'aws4_request')
    return k_signing

print 'Lambda function starting'

# defines a s3 boto client
s3 = boto3.client('s3')


# main function, started by lambda
def lambda_handler(event, context):
    print("Received event")
    # attribute bucket and file name/path to variables
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']

    # where to save the downloaded file
    file_path = '/tmp/ctlogfile.gz'

    # downloads file to above path
    s3.download_file(bucket, key, file_path)

    # opens gz file for reading
    gzfile = gzip.open(file_path, "r")

    # loads contents of the Records key into variable (our actual cloudtrail log entries!)
    response = json.loads(gzfile.readlines()[0])["Records"]

    # loops over the events in the json
    for i in response:
        # leave the boring and useless events out to not flood our elasticsearch db
        # if you want these just remove this line and indent down the block
        if not(
                i["eventSource"] == "elasticloadbalancing" and
                i["eventName"] == "describeInstanceHealth" and
                i["userIdentity.userName"] == "secret_username"
        ):
            """
            Prints go to cloudwatch logs ;) easy way to debug or get more information on your logs.
            I have my logs on cloudwatch set to erase in 1 day, so I go really verbose here.
            """

            print 'Sending event to elasticsearch'

            # adds @timestamp field = time of the event
            i["@timestamp"] = i["eventTime"]

            # removes .aws.amazon.com from eventsources
            i["eventSource"] = i["eventSource"].split(".")[0]
            data = json.dumps(i)

            # defines correct index name based on eventTime, so we have an index for each day on ES
            event_date = i["eventTime"].split("T")[0].replace("-", ".")

            # url endpoint for our ES cluster
            url = 'https://'+host+'/logstash-'+event_date+'/cloudtrail/'
            print "url :", url
            print "data: ", data

            # aws signed url stuff - for comments on this check their example page linked on top comment
            t = datetime.datetime.utcnow()
            amz_date = t.strftime('%Y%m%dT%H%M%SZ')
            date_stamp = t.strftime('%Y%m%d')
            canonical_uri = '/logstash-'+event_date+'/cloudtrail/'
            canonical_querystring = ''
            canonical_headers = 'content-type:' + content_type + '\n' + \
                                'host:' + host + '\n' + \
                                'x-amz-date:' + amz_date + '\n'
            signed_headers = 'content-type;host;x-amz-date'
            payload_hash = hashlib.sha256(data).hexdigest()
            canonical_request = method + '\n' + \
                                canonical_uri + '\n' + \
                                canonical_querystring + '\n' + \
                                canonical_headers + '\n' + \
                                signed_headers + '\n' + \
                                payload_hash
            algorithm = 'AWS4-HMAC-SHA256'
            credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
            string_to_sign = algorithm + '\n' + \
                             amz_date + '\n' + \
                             credential_scope + '\n' + \
                             hashlib.sha256(canonical_request).hexdigest()
            signing_key = get_signature_key(secret_key, date_stamp, region, service)
            signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
            authorization_header = algorithm + ' ' + \
                                   'Credential=' + access_key + '/' + credential_scope + ', ' + \
                                   'SignedHeaders=' + signed_headers + ', ' + \
                                   'Signature=' + signature
            headers = {'Content-Type':content_type,
                       'X-Amz-Date':amz_date,
                       'Authorization':authorization_header, 'X-Amz-Security-Token': session_token}

            # sends the json to elasticsearch
            req = requests.post(url, data=data, headers=headers)
            print "status code: ", req.status_code
            print "text", req.text

            retry_counter = 1

            """
            if we fail for some reason we will retry 3 times
            you will most likely have errors if you're copying a huge ammount of logs from an old bucket
            to your new one.

            For normal usage you shouldnt have to worry about this.
            I got it in production with 90 aws accounts pointing to the same bucket,
            and a pair of m3.mediums on the ES cluster, with 0 errors.

            I dont raise an exception on errors to not miss all the other entries in the file, or risk repeating any
            inserts done before the error.
            """

            # if our status code is not successfull, and our retry counter is less than 4
            while req.status_code != 201 and retry_counter < 4:
                print "retry", retry_counter, "of 3 - failed sending data to elasticsearch:", req.status_code

                # send the data to ES again
                req = requests.post(url, data=data, headers=headers)

                # if it worked this time, nice! \o/
                if req.status_code == 201:
                    print "data successfully sent!"
                print "status code: ", req.status_code
                print "text", req.text
                retry_counter += 1

    print "all done for this file!"
