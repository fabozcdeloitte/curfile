import boto3
import json
from botocore.exceptions import ClientError
import logging


def get_inputs():
    """inputs from user

    profile - profile name from where user runs the script
    report_name - name for the cur report generated
    source_bucket_prefix - prefix of the s3 bucket that will be created
    client_name
    s3_region - region where s3 bucket lies
    dest_account_number - account where the cur report needs to be replicated
    dest_bucket_arn - bucket arn where the cur report needs to be replicated
    iam_role_name - no need to modify
    policy_name - no need to modify
    """
    profile = "CLOUDECONOMICS-ADMIN-NPD"
    report_name = "DCMS_CUR"
    client_name = "DUIndia-didimqwk"
    source_bucket_prefix = "-cur-report-bucket"
    s3_region = "us-east-2"
    dest_account_number = "125923574714"
    dest_bucket_arn = "arn:aws:s3:::cldecotest"
    iam_role_name = "testing-cur-iam-v2"
    policy_name = "cur-iam-policy-v2"

    # session creation and clients for services s3, iam and cur
    session = boto3.Session(profile_name=profile, region_name="us-east-1")
    s3_client = session.client("s3")
    iam_client = session.client("iam")
    cur_client = session.client("cur")

    source_bucket_name = client_name + source_bucket_prefix
    source_bucket_arn = "arn:aws:s3:::" + source_bucket_name
    source_bucket_arn_prefix = source_bucket_arn + "/*"
    dest_bucket_arn_prefix = dest_bucket_arn + "/*"
    # check if the bucket already exists
    bucket_availability = bucket_exists(s3_client, source_bucket_name)

    # if bucket doesn't exist, create bucket, enable versioniong,
    # set up bucket policy, create iam role, iam policy and attach them
    # set up bucket replication, generate cur report
    if not bucket_availability:
        create_bucket(profile, source_bucket_name, s3_region)
        bucket_versioning(s3_client, source_bucket_name)
        set_bucket_policy(s3_client, source_bucket_name, source_bucket_arn)
        iam_arn = create_iam_role(
            iam_client,
            iam_role_name,
            policy_name,
            source_bucket_arn,
            source_bucket_arn_prefix,
            dest_bucket_arn,
            dest_bucket_arn_prefix,
        )
        bucket_replication(
            s3_client, source_bucket_name, iam_arn, dest_bucket_arn, dest_account_number
        )
        generate_cur_report(cur_client, report_name, source_bucket_name, client_name, s3_region)
    # if bucket already exists, generate cur report
    else:
        generate_cur_report(cur_client, report_name, source_bucket_name, client_name, s3_region)


def bucket_exists(s3_client, source_bucket_name):
    """Checks if source_bucket_name already exists,

    if yes, returns True
    else, False
    """
    bucket_names = []
    response = s3_client.list_buckets()
    buckets = response["Buckets"]
    for bucket in buckets:
        bucket_names.append(bucket["Name"])
    if source_bucket_name in bucket_names:
        print("Bucket exists")
        return True
    else:
        print("Bucket doesn't exist")
        return False


def create_bucket(profile, source_bucket_name, s3_region):
    """Creates an S3 bucket in a specified region

    If a region is not specified, the bucket is created in the S3 default
    region (us-east-1)
    """
    profile = profile
    session = boto3.Session(profile_name=profile, region_name="us-east-1")
    s3_client = session.client("s3")
    try:
        if s3_region is None:
            s3_client.create_bucket(Bucket=source_bucket_name)
        else:
            s3_client = session.client("s3", region_name=s3_region)
            location = {"LocationConstraint": s3_region}
            s3_client.create_bucket(Bucket=source_bucket_name, CreateBucketConfiguration=location)
    except ClientError as e:
        logging.error(e)
        return False
    return True


def bucket_versioning(s3_client, source_bucket_name):
    """Enables versioning for s3 bucket"""
    response = s3_client.put_bucket_versioning(
        Bucket=source_bucket_name,
        VersioningConfiguration={"Status": "Enabled"},
    )
    print(response)


def set_bucket_policy(s3_client, source_bucket_name, source_bucket_arn):
    """Sets up a bucket policy"""
    source_bucket_arn_resource = source_bucket_arn + "/*"
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "billingreports.amazonaws.com"},
                "Action": ["s3:GetBucketAcl", "s3:GetBucketPolicy"],
                "Resource": source_bucket_arn,
            },
            {
                "Effect": "Allow",
                "Principal": {"Service": "billingreports.amazonaws.com"},
                "Action": ["s3:PutObject", "s3:PutObjectAcl"],
                "Resource": source_bucket_arn_resource,
            },
        ],
    }
    print(bucket_policy)
    # Convert the policy from JSON dict to string
    bucket_policy = json.dumps(bucket_policy)
    # Set the new policy
    response = s3_client.put_bucket_policy(Bucket=source_bucket_name, Policy=bucket_policy)
    print(response)


def create_iam_role(
    iam_client,
    iam_role_name,
    policy_name,
    source_bucket_arn,
    source_bucket_arn_prefix,
    dest_bucket_arn,
    dest_bucket_arn_prefix,
):
    """Creates an iam role, iam policy and attaches the iam policy to the iam role"""
    role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": [
                    "s3:ListBucket",
                    "s3:GetReplicationConfiguration",
                    "s3:GetObjectVersionForReplication",
                    "s3:GetObjectVersionAcl",
                    "s3:GetObjectVersionTagging",
                    "s3:GetObjectRetention",
                    "s3:GetObjectLegalHold",
                ],
                "Effect": "Allow",
                "Resource": [
                    source_bucket_arn,
                    source_bucket_arn_prefix,
                    dest_bucket_arn,
                    dest_bucket_arn_prefix,
                ],
            },
            {
                "Action": [
                    "s3:ReplicateObject",
                    "s3:ReplicateDelete",
                    "s3:ReplicateTags",
                    "s3:ObjectOwnerOverrideToBucketOwner",
                ],
                "Effect": "Allow",
                "Resource": [
                    source_bucket_arn,
                    source_bucket_arn_prefix,
                    dest_bucket_arn,
                    dest_bucket_arn_prefix,
                ],
            },
        ],
    }

    trust_relationship = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    trust_relationship = json.dumps(trust_relationship)
    role_policy = json.dumps(role_policy)
    description = "IAM role to replicate CUR report"
    response = iam_client.create_role(
        RoleName=iam_role_name,
        AssumeRolePolicyDocument=trust_relationship,
        Description=description,
    )
    iam_arn = response["Role"]["Arn"]
    print("iam_arn is: " + iam_arn)
    print(response)
    policy_response = iam_client.create_policy(
        PolicyName=policy_name,
        PolicyDocument=role_policy,
        Description=description,
    )
    print("policy response is")
    print(policy_response)
    policy_arn = policy_response["Policy"]["Arn"]
    print("policy_arn is: " + policy_arn)
    attach_policy_response = iam_client.attach_role_policy(
        RoleName=iam_role_name, PolicyArn=policy_arn
    )
    print(attach_policy_response)
    return iam_arn


def bucket_replication(
    s3_client, source_bucket_name, source_iam_role, dest_bucket_name, dest_account_number
):
    """Sets up Cross region replication"""
    response = s3_client.put_bucket_replication(
        Bucket=source_bucket_name,
        ReplicationConfiguration={
            "Role": source_iam_role,
            "Rules": [
                {
                    "Destination": {
                        "Bucket": dest_bucket_name,
                        "Account": dest_account_number,
                        "AccessControlTranslation": {"Owner": "Destination"},
                    },
                    "Prefix": "",
                    "Status": "Enabled",
                },
            ],
        },
    )
    print(response)


def generate_cur_report(cur_client, report_name, source_bucket_name, client_name, s3_region):
    """Generates cur report"""
    response = cur_client.put_report_definition(
        ReportDefinition={
            "ReportName": report_name,
            "TimeUnit": "HOURLY",
            "Format": "textORcsv",
            "Compression": "GZIP",
            "AdditionalSchemaElements": [
                "RESOURCES",
            ],
            "S3Bucket": source_bucket_name,
            "S3Prefix": client_name,
            "S3Region": s3_region,
            "AdditionalArtifacts": ["REDSHIFT", "QUICKSIGHT"],
            "RefreshClosedReports": True,
            # "ReportVersioning": "OVERWRITE_REPORT",
            "ReportVersioning": "CREATE_NEW_REPORT",
        }
    )
    print(response)


get_inputs()
