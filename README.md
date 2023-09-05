# Table of Contents

- [Introduction](#introduction)
- [IAM Permission](#iam-permissions)
- [Lambda](#lambda)
- [Event Bridge](#event-bridge)

# Introduction
This project helps to remediate newly created ec2 security groups created with 0.0.0.0/0 with approved subnet defined in lambda variable. Also validates if the creation of the group is from group defined in exclude group (example Operations group who can only create groups with 0.0.0.0/0).
We will be using below events from event bridge rules to capure changes to security groups and call lambda fuction which can remediate the security groups.

AuthorizeSecurityGroupIngress
AuthorizeSecurityGroupEgress
ModifySecurityGroupRules


# IAM Permissions
Please create IAM role with below permissions to use for lambda function.

{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "ec2:RevokeSecurityGroupIngress",
                "ec2:AuthorizeSecurityGroupEgress",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupEgress",
                "ec2:ModifySecurityGroupRules”,
		 "iam:GetGroup"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:us-east-1:<Account>:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:us-east-1:<Account>:log-group:/aws/lambda/ec2-sg-state-change:*"
            ]
        }
    ]
}


# Lambda
Create lambda function (example: ec2-security-group-remediation), use IAM policy above. During testing python 3.10 was selected as runtime. For the function to work, please add below 2 variable once created.

EXCLUDE_GROUP = "Add the group name who's allowed to create 0.0.0.0/0 CIDR, if matching fuction will skip running the checks"
PREDEFINED_CIDR = <Input CIDR that you want to replace 0.0.0.0/0 with"

Lambda timeout was increased to 30 seconds for APIs to work, tune as required.

Deploy lambda from function attached "ec2-sg-state-change.py"

# Event Bridge

Create Event Bridge Rule with below event pattern, select target as lambda function created above.

{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "ModifySecurityGroupRules"]
  }
}







