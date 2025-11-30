# AWS IAM Boto3 Demo

### Description
This script demonstrates some of the core functionality of the AWS boto3 library:
  - Viewing the defined permanent IAM users for the AWS account
  - Viewing the defined roles available in the account
  - Viewing the human readable account alias
  - Setting or deleting the existing alias
  - Viewing a usage summary for the account
  - Assuming a pre-defined role and applying the temporary credentials to the current script execution
  - Listing all S3 buckets hosted in the account

### Required Packages
See [requirements.txt](requirements.txt)

### Installation
- Clone the repo.
- Change directory to project root, e.g. ```cd awsiamdev```
- ```pip install -r requirements.txt```

### Usage
1. Install the demo.
2. Configure the credentials required to access your AWS account as per [the boto3 documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html). The initial IAM permissions required for script functionality are:
  - [iam:ListUsers](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListUsers.html)
  - [iam:ListGroupsForUser](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListGroupsForUser.html)
  - [iam:ListAttachedGroupPolicies](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAttachedGroupPolicies.html)
  - [iam:ListGroupPolicies](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListGroupPolicies.html)
  - [iam:ListRoles](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListRoles.html)
  - [iam:ListAccountAliases](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccountAliases.html)
  - [iam:CreateAccountAlias](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccountAlias.html)
  - [iam:DeleteAccountAlias](https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteAccountAlias.html)
  - [iam:GetAccountSummary](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html)
  - [sts:AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
  - [s3:ListAllMyBuckets](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html)
3. [iam.py](iam.py) can be run in an interactive menu mode by executing it with no arguments, i.e. ```python iam.py```. Commands can also be executed directly by providing the command name and any necessary command arguments, e.g. ```python iam.py create-alias PleaseSirCanIHaveAnAlias```.
