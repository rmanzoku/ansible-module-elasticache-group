#!/usr/bin/python
# coding: utf-8

try:
    import boto
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False

try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

try:
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTOCORE = True
except ImportError:
    HAS_BOTOCORE = False

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ec2 import ec2_argument_spec, boto3_conn, get_aws_connection_info


def ec2groups_grants(module, conn, name, present_ec2groups, desire_ec2groups):
    authorize_ec2groups = [i for i in desire_ec2groups if i not in present_ec2groups]
    revoke_ec2groups = [i for i in present_ec2groups if i not in desire_ec2groups]

    if (len(authorize_ec2groups) == 0) and (len(revoke_ec2groups) == 0):
        return False

    if len(authorize_ec2groups) != 0:
        for i in authorize_ec2groups:
            try:
                conn.authorize_db_security_group_ingress(
                    DBSecurityGroupName=name,
                    EC2SecurityGroupName=i['group_name'],
                    EC2SecurityGroupOwnerId=i['group_owner_id']
                )
            except ClientError as ex:
                module.fail_json(msg=ex.response['Error']['Message'])

    if len(revoke_ec2groups) != 0:
        for i in revoke_ec2groups:
            try:
                conn.revoke_db_security_group_ingress(
                    DBSecurityGroupName=name,
                    EC2SecurityGroupName=i['group_name'],
                    EC2SecurityGroupOwnerId=i['group_owner_id']
                )
            except ClientError as ex:
                module.fail_json(msg=ex.response['Error']['Message'])

    return True


def ipranges_grants(module, conn, name, present_ipranges, desire_ipranges):
    authorize_ipranges = list(set(desire_ipranges) - set(present_ipranges))
    revoke_ipranges = list(set(present_ipranges) - set(desire_ipranges))

    if (len(authorize_ipranges) == 0) and (len(revoke_ipranges) == 0):
        return False

    if len(authorize_ipranges) != 0:

        try:
            for i in authorize_ipranges:
                conn.authorize_db_security_group_ingress(
                    DBSecurityGroupName=name,
                    CIDRIP=i
                )
        except ClientError as ex:
            module.fail_json(msg=ex.response['Error']['Message'])

    if len(revoke_ipranges) != 0:
        try:
            for i in revoke_ipranges:
                conn.revoke_db_security_group_ingress(
                    DBSecurityGroupName=name,
                    CIDRIP=i
                )
        except ClientError as ex:
            module.fail_json(msg=ex.response['Error']['Message'])

    return True


def main():

    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type='str', required=True),
            description=dict(type='str', required=True),
            ip_ranges=dict(type='list', default=[]),
            ec2_security_groups=dict(type='list', default=[]),
            state=dict(default='present', type='str', choices=['present', 'absent']),
        )
    )

    module = AnsibleModule(argument_spec=argument_spec)

    # Dict inside ec2_security_groups has string values
    module.params['ec2_security_groups'] = [{'group_owner_id': str(i['group_owner_id']),
                                             'group_name': str(i['group_name'])}
                                            for i in module.params['ec2_security_groups']]

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 required for this module')
    if not HAS_BOTO:
        module.fail_json(msg='boto required for this module')
    if not HAS_BOTOCORE:
        module.fail_json(msg='botocore required for this module')

    # Connect to AWS
    try:
        region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
        conn = boto3_conn(module, conn_type="client", resource="rds", region=region,
                          **aws_connect_kwargs)
    except NoCredentialsError as ex:
        module.fail_json(msg=ex.message)

    changed = False

    # Absent
    if module.params['state'] == "absent":
        try:
            conn.delete_db_security_group(DBSecurityGroupName=module.params['name'])
            changed = True
        except ClientError as ex:
            if ex.response['Error']['Code'] == "DBSecurityGroupNotFound":
                changed = False
            else:
                module.fail_json(msg=ex.response['Error']['Message'])

        module.exit_json(changed=changed)

    # Present
    else:
        try:
            conn.create_db_security_group(DBSecurityGroupName=module.params['name'],
                                          DBSecurityGroupDescription=module.params['description'])
            changed = True
        except ClientError as ex:
            if ex.response['Error']['Code'] == "DBSecurityGroupAlreadyExists":
                changed = False
            else:
                module.fail_json(msg=ex.response['Error']['Message'])

    # Security group exists
    result = conn.describe_db_security_groups(DBSecurityGroupName=module.params['name'])

    # IP CIDR based roles
    if len(result['DBSecurityGroups'][0]['IPRanges']) == 0:
        present_ipranges = []
    else:
        present_ipranges = [i['CIDRIP'] for i in result['DBSecurityGroups'][0]['IPRanges']
                            if ((i['Status'] == "authorized") or (i['Status'] == "authorizing"))]

    changed = ipranges_grants(module, conn, module.params['name'],
                              present_ipranges, module.params['ip_ranges']) or changed

    # ec2 security group based rules
    if len(result['DBSecurityGroups'][0]['EC2SecurityGroups']) == 0:
        present_ec2groups = []
    else:
        present_ec2groups = [
            {"group_owner_id": i['EC2SecurityGroupOwnerId'],
             "group_name": i['EC2SecurityGroupName']}
            for i in result['DBSecurityGroups'][0]['EC2SecurityGroups']
            if ((i['Status'] == "authorized") or (i['Status'] == "authorizing"))]

    changed = ec2groups_grants(module, conn, module.params['name'],
                               present_ec2groups, module.params['ec2_security_groups']) or changed

    module.exit_json(changed=changed)


if __name__ == '__main__':
    main()
