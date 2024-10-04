# AWS Route53 Dynamic DNS Updater

This script will update a Route53 DNS record with the current public IP address of the machine it is running on.
It will poll every minute and update the record if the IP address has changed.

## Usage

Create a new IAM user with the following policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "route53:ChangeResourceRecordSets",
                "route53:GetHostedZone",
                "route53:ListResourceRecordSets"
            ],
            "Resource": [
                "arn:aws:route53:::hostedzone/*"
            ]
        }
    ]
}
```

Then create a new file .env with the following content:

```
AWS_ACCESS_KEY_ID=your_access_key_id
AWS_SECRET_ACCESS_KEY=your_secret_access_key
AWS_HOSTED_ZONE_ID=your_hosted_zone_id
AWS_RECORD_NAME=your_record_name
AWS_REGION=your_region
```

Finally, run the docker-compose file:

```bash
docker-compose up -d
```
