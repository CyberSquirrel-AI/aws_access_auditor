# AWS Access Auditor

**AWS Access Auditor** is a Python-based CLI tool that allows penetration testers, cloud engineers, and auditors to **enumerate which AWS services are accessible** using a given Access Key and Secret Key. It's designed to be lightweight, silent on failure, and highly extensible.

## 🔍 Use Case

You've discovered AWS credentials in an environment file, container, or via IAM misconfiguration. You want to **quickly and safely test** what services those credentials can access — without triggering alarms or performing risky operations.

This tool does exactly that.

## ✅ Features

- Verifies credential validity using `sts.get_caller_identity()`
- Attempts harmless read-only API calls to 30+ AWS services
- Prints real-time allowed services
- Provides a clean summary report at the end
- Optional logging to a file

## 🚀 Installation

```# Clone the repository
git clone git@github.com:CyberSquirrel-AI/aws_access_auditor.git

# Navigate into the project directory
cd aws-access-auditor

# Create a virtual environment named 'venv'
python3 -m venv venv

# Activate the virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows:
venv\Scripts\activate

# Install the required package
pip install boto3
```

## 🛠️ Usage


```bash
python aws_access_auditor.py \
  --access-key YOUR_ACCESS_KEY \
  --secret-key YOUR_SECRET_KEY \
  --log-file optional_output.log
```

You’ll see output like:

```text
Access to S3 is ALLOWED.
Access to Lambda is ALLOWED.
...
Summary of allowed services:
- S3
- Lambda
- EC2
```

## 🔒 Stealth Considerations

- Uses only `list_*` or `describe_*` API calls
- No modification, deletion, or creation of any resource
- Silently skips access-denied services

## 📁 Supported Services

- EC2, S3, Lambda, IAM, RDS, DynamoDB
- ECS, EKS, CloudTrail, CloudWatch
- API Gateway, Route 53, Kinesis, SQS, SNS
- Elasticache, EFS, Redshift, SageMaker, Aurora
- GuardDuty, Config, WAF, ACM, ACM PCA
- Secrets Manager, ELB, CloudFormation, ECR
- Glue, Athena, Backup, Code* services

## 📌 Disclaimer

> This tool is intended for **authorized testing and audit use only**. Misuse against environments you don't own or operate is illegal and unethical.

## 📄 License

MIT License

---

Built with ❤️ by CyberSquirrel.
