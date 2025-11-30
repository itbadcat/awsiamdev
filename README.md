# AWS IAM Boto3 Demo

### Description
These scripts demonstrate some of the core functionality of the AWS boto3 library.

### Required Packages
See [requirements.txt](requirements.txt)

### Installation
- Clone the repo
- ```pip install -r requirements.txt```

### Usage
1. Install the demo.
2. Configure the credentials required to access your account as per [the boto3 documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html). The initial IAM permissions required for script functionality are:
  - [iam:ListUsers](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListUsers.html)
  - [iam:ListGroupsForUser](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListGroupsForUser.html)
  - [iam:ListAttachedGroupPolicies](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAttachedGroupPolicies.html)
  - [iam:ListGroupPolicies](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListGroupPolicies.html)
  - [iam:ListRoles](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListRoles.html)
  - [iam:CreateAccountAlias](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccountAlias.html)
  - [iam:DeleteAccountAlias](https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteAccountAlias.html)
  - [iam:GetAccountSummary](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html)
  - [sts:AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
  - [s3:ListAllMyBuckets](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html)
3. [iam.py](iam.py) can be run in an interactive mode by executing it with no arguments. Commands can also be executed directly by providing the command name and any necessary command arguments, e.g. ```python iam.py create-alias thebestaliasever```.
