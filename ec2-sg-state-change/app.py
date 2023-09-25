import json
import os
import boto3

# Set the group name you want to check against
GROUP_NAME_TO_CHECK = os.environ["EXCLUDE_GROUP"]
PREDEFINED_CIDR = os.environ["PREDEFINED_CIDR"]

# Function to parse username and check group membership
def get_username_and_check_group(event):
    # Try to get username from userIdentity
    if 'userIdentity' in event['detail'] and 'userName' in event['detail']['userIdentity']:
        username = event['detail']['userIdentity']['userName']
    # If userIdentity doesn't have userName, try to get from sessionIssuer
    elif 'userIdentity' in event['detail'] and 'sessionContext' in event['detail']['userIdentity'] and 'sessionIssuer' in event['detail']['userIdentity']['sessionContext']:
        username = event['detail']['userIdentity']['sessionContext']['sessionIssuer']['userName']
    # If neither userIdentity nor sessionIssuer have userName, return None
    else:
        username = None

    # Check if username is in the specified group
    iam_client = boto3.client('iam')
    response = iam_client.get_group(GroupName=GROUP_NAME_TO_CHECK)
    if 'Users' in response and any(user['UserName'] == username for user in response['Users']):
        print(f"User '{username}' is part of '{GROUP_NAME_TO_CHECK}' group. Skipping logic.")
        return {
            'statusCode': 200,
            'body': json.dumps(f"User is part of {GROUP_NAME_TO_CHECK} group. Skipping logic.")
        }

    return username

# Main function
def lambda_handler(event, context):
    # Print the incoming event for debugging purposes
    #print("Received event:", json.dumps(event, indent=2))
    
    # Retrieve environment variables
    username = get_username_and_check_group(event)
    
    # If not in specified group, continue with processing
    # Check if the event contains relevant details
    if 'detail' in event and 'eventName' in event['detail']:
        event_name = event['detail']['eventName']
        
        # Check if the event is related to security group changes
        if event_name in [
            'AuthorizeSecurityGroupIngress',
            'AuthorizeSecurityGroupEgress',
            'ModifySecurityGroupRules'
        ]:
            # Extract security group ID and rule details
            if event_name == 'ModifySecurityGroupRules':
                security_group_id = event['detail']['requestParameters']['ModifySecurityGroupRulesRequest']['GroupId']
                # Extract the rule details
                rule = event['detail']['requestParameters']['ModifySecurityGroupRulesRequest']['SecurityGroupRule']
                security_group_rule_id = rule['SecurityGroupRuleId']
                if 'CidrIpv4' in rule['SecurityGroupRule']:
                     cidr_ip = rule['SecurityGroupRule']['CidrIpv4']
                else:
                     cidr_ip = rule['SecurityGroupRule']['CidrIpv6']
                from_port = rule['SecurityGroupRule']['FromPort']
                to_port = rule['SecurityGroupRule']['ToPort']
                ip_protocol = rule['SecurityGroupRule']['IpProtocol']
                rule_id = f"{ip_protocol}_{from_port}_{to_port}_{cidr_ip}"
                # Create a rule detail dictionary
                rule_details = [{
                    'CIDR IP': cidr_ip,
                    'Security Group ID': security_group_id,
                    'Rule ID': rule_id,
                    'FromPort': from_port,
                    'ToPort': to_port,
                    'IpProtocol': ip_protocol,
                    'SecurityGroupRuleID': security_group_rule_id,
                }]
            else:
                security_group_id = event['detail']['requestParameters']['groupId']
                # Extract all CIDR IP addresses, security group IDs, and rule IDs
                ip_permissions = event['detail']['requestParameters']['ipPermissions']['items']
                rule_details = []
                for ip_permission in ip_permissions:
                    # Check for IPv4 rules
                    if 'ipRanges' in ip_permission and 'items' in ip_permission['ipRanges']:
                        for item in ip_permission['ipRanges']['items']:
                           cidr_ip = item['cidrIp']
                           #rule_id = f"{ip_permission['ipProtocol']}_{ip_permission['fromPort']}_{ip_permission['toPort']}_{cidr_ip}"
                           rule_details.append({
                            'CIDR IP': cidr_ip,
                            'Security Group ID': security_group_id,
                            'IpProtocol': ip_permission['ipProtocol'],
                            'FromPort': ip_permission['fromPort'],
                            'ToPort': ip_permission['toPort'],
            		   })
                    # Check for IPv6 rules
                    if 'ipv6Ranges' in ip_permission and 'items' in ip_permission['ipv6Ranges']:
                        for item in ip_permission['ipv6Ranges']['items']:
                           cidr_ip = item['cidrIpv6']
                           rule_id = f"{ip_permission['ipProtocol']}_{ip_permission['fromPort']}_{ip_permission['toPort']}_{cidr_ip}"
                           rule_details.append({
                            'CIDR IP': cidr_ip,
                            'Security Group ID': security_group_id,
                            'IpProtocol': ip_permission['ipProtocol'],
                            'FromPort': ip_permission['fromPort'],
                            'ToPort': ip_permission['toPort'],
                        })
            
            # Update rules with the predefined CIDR value for IPv4
            for rule in rule_details:
                print(rule)
                if rule['CIDR IP'] in ['0.0.0.0/0', '::/0']:  # Check for both IPv4 and IPv6 '0.0.0.0/0' or '::/0'
                    # Create a new rule with the predefined CIDR value for IPv4
                    if event_name == 'ModifySecurityGroupRules':
                    	new_rule_ipv4 = {
                        	'SecurityGroupRuleId': rule['SecurityGroupRuleID'],
                        	'SecurityGroupRule': {
                                'CidrIpv4': PREDEFINED_CIDR,
                                'FromPort': rule['FromPort'],
                                'ToPort': rule['ToPort'],
                                'IpProtocol': rule['IpProtocol'],
                    	    }
                    	}

                    else: 
                        new_rule_ipv4 = {
                    	    'IpProtocol': rule['IpProtocol'],
                        	'FromPort': rule['FromPort'],
                        	'ToPort': rule['ToPort'],
                        	'IpRanges': [{'CidrIp': PREDEFINED_CIDR}]
                    	}
                        if rule['CIDR IP'] == '0.0.0.0/0':
                            old_rule_delete = {
                                'IpProtocol': rule['IpProtocol'],
                                'FromPort': rule['FromPort'],
                                'ToPort': rule['ToPort'],
                                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                            }
                        else:
                            old_rule_delete = {
                                'IpProtocol': rule['IpProtocol'],
                                'FromPort': rule['FromPort'],
                                'ToPort': rule['ToPort'],
                                'Ipv6Ranges': [{'CidrIpv6': '::/0'}]
                            }
                        
                    try:
                        ec2_client = boto3.client('ec2')
                        if event_name == 'AuthorizeSecurityGroupIngress':
                            print(old_rule_delete)
                            ec2_client.revoke_security_group_ingress(
                                GroupId=security_group_id,
                                IpPermissions=[old_rule_delete]
                            )
                            print(new_rule_ipv4)
                            ec2_client.authorize_security_group_ingress(
                                GroupId=security_group_id,
                                IpPermissions=[new_rule_ipv4]
                            )
                            print(f"Updated ingress rule in security group {security_group_id} with CIDR: {PREDEFINED_CIDR}")
                        elif event_name == 'AuthorizeSecurityGroupEgress':
                            ec2_client.revoke_security_group_egress(
                                GroupId=security_group_id,
                                IpPermissions=[old_rule_delete]
                            )
                            ec2_client.authorize_security_group_egress(
                                GroupId=security_group_id,
                                IpPermissions=[new_rule_ipv4]
                            )
                            print(f"Updated egress rule in security group {security_group_id} with CIDR: {PREDEFINED_CIDR}")
                        elif event_name == 'ModifySecurityGroupRules':
                            ec2_client.modify_security_group_rules(
                                GroupId=security_group_id,
                                SecurityGroupRules=[new_rule_ipv4]
                            )
                            print(f"Updated security group rule in security group {security_group_id} with CIDR: {PREDEFINED_CIDR}")
                    except Exception as e:
                        print("Error updating rule:", str(e))
            
            # You can perform further actions with the extracted data here
            
            return {
                'statusCode': 200,
                'body': json.dumps('Processing complete')
            }
    else:
        return {
            'statusCode': 400,
            'body': json.dumps('Invalid event format')
        }
