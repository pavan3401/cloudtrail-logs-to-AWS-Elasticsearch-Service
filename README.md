# cloudtrail-logs-to-AWS-Elasticsearch-Service. This code is based https://github.com/argais/cloudtrail_aws_es.git. Modified the code to get temporary credentials from attached role instead of hardcoding the credentials.

Automatically put your cloudtrail logs into Amazon Elasticsearch Service! and get a nice Kibana interface for it ;)

Cloudtrail, we all need it, and hey, its fairly easy to check stuff on the console.
Now, if you have multiple AWS accounts, it starts to get hairy, nobody wants to keep jumping over account consoles for that right?

Enter automation to save your skin!

## Requirements

- basic knowledge of all the aws services involved (s3, lambda, elasticsearch, cloudtrail)
- cloudtrail already set to store logs in an s3 bucket
- elasticsearch cluster ready

## Steps

Assuming some basic knowledge of the services involved.

- clone this repo
- on your terminal, install the requests module on the same folder with ```pip install requests -t .```
- edit s3_lambda_es.py changing the following variables
  - host = the full hostname for your AWS ES endpoint
  - region = region were your ES cluster is located
- Curl the elastic_search_cloudtrail_template.json file contents on your ES cluster
- create a new lambda function
  - for uploading the code zip this entire folder and upload away (can keep readme, elastic_search_cloudtrail_template.json and .gitignore out). Very important! The files must be on the root of the zip, not inside a folder.
  - zip -r name-the-contents.zip . 
  - handler for the function is s3_lambda_es.lambda_handler
  - lambda role must allow access to the cloudtrail s3 bucket, and to create logs on cloudwatch
- Go to properties of S3 Bucket that is holding your cloudtrail logs,
  - click on Events
  - Add Notification,
  - Give name to it
  - In the Events Line, select ObjectCreated(ALL)
  - Then Send To Select the lambda function
  - Select the lambda function you created
- done! go check your kibana now and see the data flowing in ;)
- Click Kibana Url
-Give logstash-*
-Select @timestamp in the Time-field drop down and click create.

## Notes

For more detailed post check feranando's blog(https://www.fernandobattistella.com.br/log_processing/2016/03/13/Cloudtrail-S3-Lambda-Elasticsearch.html).

## Lambda logs

On lambda web console, in the monitoring tab, theres a link for its logs on cloudwatch, you can see what the lambda function is doing.
