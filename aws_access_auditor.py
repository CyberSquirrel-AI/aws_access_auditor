import boto3
from botocore.exceptions import ClientError
import argparse
import logging

def parse_arguments():
    # Parse CLI arguments including optional log file output
    parser = argparse.ArgumentParser(description="Check AWS services access using AWS Access Key and Secret Key")
    parser.add_argument('--access-key', required=True, help="AWS Access Key ID")
    parser.add_argument('--secret-key', required=True, help="AWS Secret Access Key")
    parser.add_argument('--log-file', help="Optional: Path to a log file")
    return parser.parse_args()

def check_service_access(service_name, client_method, results):
    try:
        client_method()
        print(f"Access to {service_name} is ALLOWED.")
        logging.info(f"Access to {service_name} is ALLOWED.")
        results.append(service_name)
    except Exception:
        pass

def main():
    args = parse_arguments()

    # Setup logging after parsing arguments
    if args.log_file:
        logging.basicConfig(filename=args.log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # First, validate the credentials by making a lightweight IAM call
    session = boto3.Session(
        aws_access_key_id=args.access_key,
        aws_secret_access_key=args.secret_key,
    )

    # Validate credentials
    try:
        sts_client = session.client('sts')
        identity = sts_client.get_caller_identity()
        print(f"Credentials are valid. Account: {identity['Account']}, UserID: {identity['UserId']}")
        logging.info(f"Credentials validated for Account: {identity['Account']}, UserID: {identity['UserId']}")
    except ClientError as e:
        print("Invalid AWS credentials. Exiting.")
        logging.error("Invalid AWS credentials provided.")
        return

    print("Checking access to top AWS services...\n")

    services = {
        # Existing services
        'EC2': (session.client('ec2'), lambda c: c.describe_instances()),
        'S3': (session.client('s3'), lambda c: c.list_buckets()),
        'IAM': (session.client('iam'), lambda c: c.list_users()),
        'Lambda': (session.client('lambda'), lambda c: c.list_functions()),
        'RDS': (session.client('rds'), lambda c: c.describe_db_instances()),
        'DynamoDB': (session.client('dynamodb'), lambda c: c.list_tables()),
        'CloudWatch': (session.client('cloudwatch'), lambda c: c.describe_alarms()),
        'CloudFormation': (session.client('cloudformation'), lambda c: c.list_stacks()),
        'SNS': (session.client('sns'), lambda c: c.list_topics()),
        'SQS': (session.client('sqs'), lambda c: c.list_queues()),
        'VPC': (session.client('ec2'), lambda c: c.describe_vpcs()),
        'ECS': (session.client('ecs'), lambda c: c.list_clusters()),
        'EKS': (session.client('eks'), lambda c: c.list_clusters()),
        'CloudTrail': (session.client('cloudtrail'), lambda c: c.lookup_events()),
        'KMS': (session.client('kms'), lambda c: c.list_keys()),
        'ELB': (session.client('elb'), lambda c: c.describe_load_balancers()),
        'Secrets Manager': (session.client('secretsmanager'), lambda c: c.list_secrets()),
        'API Gateway': (session.client('apigateway'), lambda c: c.get_rest_apis()),
        'Route 53': (session.client('route53'), lambda c: c.list_hosted_zones()),
        'WAF': (session.client('wafv2'), lambda c: c.list_web_acls()),
        'ECR': (session.client('ecr'), lambda c: c.describe_repositories()),
        'Elasticache': (session.client('elasticache'), lambda c: c.describe_cache_clusters()),
        'Step Functions': (session.client('stepfunctions'), lambda c: c.list_state_machines()),
        'EFS': (session.client('efs'), lambda c: c.describe_file_systems()),
        'Redshift': (session.client('redshift'), lambda c: c.describe_clusters()),
        'SageMaker': (session.client('sagemaker'), lambda c: c.list_notebook_instances()),
        'Aurora': (session.client('rds'), lambda c: c.describe_db_clusters()),
        'GuardDuty': (session.client('guardduty'), lambda c: c.list_detectors()),
        'Config': (session.client('config'), lambda c: c.describe_configuration_recorder_status()),
        'ACM': (session.client('acm'), lambda c: c.list_certificates()),
        'ACM PCA': (session.client('acm-pca'), lambda c: c.list_certificate_authorities()),
        'Kinesis': (session.client('kinesis'), lambda c: c.list_streams()),
    }

    results = []
    for service_name, (client, method) in services.items():
        check_service_access(service_name, lambda: method(client), results)

    print("\nSummary of allowed services:")
    for service in results:
        print(f"- {service}")

if __name__ == "__main__":
    main()
