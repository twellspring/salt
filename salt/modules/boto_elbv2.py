# -*- coding: utf-8 -*-
'''
Connection module for Amazon ALB

:configuration: This module accepts explicit elb credentials but can also utilize
    IAM roles assigned to the instance through Instance Profiles. Dynamic
    credentials are then automatically obtained from AWS API and no further
    configuration is necessary. More Information available at:

    .. code-block:: text

        http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html

    If IAM roles are not used you need to specify them either in a pillar or
    in the minion's config file:

    .. code-block:: yaml

        elbv2.keyid: GKTADJGHEIQSXMKKRBJ08H
        elbv2.key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs
        elbv2.region: us-west-2

    If a region is not specified, the default is us-east-1.

    It's also possible to specify key, keyid and region via a profile, either
    as a passed in dict, or as a string to pull from pillars or minion config:

    .. code-block:: yaml

        myprofile:
            keyid: GKTADJGHEIQSXMKKRBJ08H
            key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs
            region: us-east-1
'''
# keep lint from choking on _get_conn and _cache_id
# pylint: disable=E0602

from __future__ import absolute_import

# Import Python libs
import logging

# Import Salt libs

# Import third party libs
# pylint: disable=3rd-party-module-not-gated
from salt.ext import six

try:
    # pylint: disable=unused-import
    import salt.utils.boto3
    # pylint: enable=unused-import

    # TODO Version check using salt.utils.versions
    from botocore.exceptions import ClientError
    logging.getLogger('boto3').setLevel(logging.CRITICAL)
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False

log = logging.getLogger(__name__)


def __virtual__():
    '''
    Only load if boto3 libraries exist.
    '''

    if not HAS_BOTO:
        return (False, "The boto_elbv2 module cannot be loaded: boto3 library not found")
    __utils__['boto3.assign_funcs'](__name__, 'elbv2')
    return True


def create(name,
           vpc_name,
           subnet_names,
           security_groups=None,
           scheme='internet-facing',
           tags=None,
           ip_type='ipv4',
           region=None,
           key=None,
           keyid=None,
           profile=None):

    '''
    .. versionadded:: XXXX.XX.XX

    Create application load balancer if not present.

    name
        (string) - The name of the application load balancer ( ALB ).
    vpn_name
        (string) - The name of the vpc the ALB will be in.
    subnet_names
        (list) - The names of the subnets to attach to the ALB. You can
                 specify only one subnet per Availability Zone. You must specify
                 subnets from at least two Availability Zones.
    security_groups
        (list) - The names or IDs of the security groups to assign to the ALB.

    scheme
        (string) - Is the ALB ``internet-facing`` ( use public IP ) or
                   ``internal`` ( use private IP )
    tags
        (dict) - tags to assing to the ALB.

    ip_type
        (string) -  The type of IP addresses used by the subnets associated with
                    the application load balancer. The possible values are ``ipv4``
                    (for IPv4 addresses) and ``dualstack`` (for IPv4 and IPv6 addresses).
                    Internal load balancers must use ipv4.

    returns
        (bool) - True on success, False on failure.

    CLI examples:
    .. code-block:: bash

        salt myminion boto_elbv2.create myExernalALB myVPC '["mySubnetA", "mySubnetB" ]' \
        security_groups='["mysecgroup1"]' ip_type='dualstack'

        salt myminion boto_elbv2.create myInternalALB myVPC '["mySubnetA", "mySubnetB" ]' \
        security_groups='["mysecgroup2"]' scheme='internal' ip_type='ipv4'
    '''

    subnets = []

    for i in subnet_names:
        resource = __salt__['boto_vpc.get_resource_id']('subnet',
                                                        name=i,
                                                        region=region,
                                                        key=key,
                                                        keyid=keyid,
                                                        profile=profile)
        if 'error' in resource:
            return (False, 'Error looking up subnet id: {0}'.format(r['error']))
        if resource['id'] is None:
            return (False, 'Subnet {0} does not exist.'.format(i))
        subnets.append(r['id'])

    _security_groups = []
    if security_groups:
        _security_groups = __salt__['boto_secgroup.convert_to_group_ids'](
            security_groups, vpc_name=vpc_name, region=region, key=key,
            keyid=keyid, profile=profile
        )
        if not _security_groups:
            return (False, 'Security groups {0} do not map to valid security group ids.'.format(security_groups))

    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
    if exists(name, region, key, keyid, profile):
        return (True, 'Application Load Balancer {0} already exists'.format(name))

    try:
        if tags is None:
            alb = conn.create_load_balancer(Name=name,
                                            Subnets=subnets,
                                            SecurityGroups=_security_groups,
                                            Scheme=scheme,
                                            IpAddressType=ip_type)
        else:
            alb = conn.create_load_balancer(Name=name,
                                            Subnets=subnets,
                                            SecurityGroups=_security_groups,
                                            Scheme=scheme,
                                            Tags=tags,
                                            IpAddressType=ip_type)
        if alb:
            log.info('Created ALB {0}'.format(name))
            return True
        else:
            log.error('Failed to create ALB {0}'.format(name))
            return (False, 'Failed to create ALB {0} reason: {1}'.format(name, alb))
    except ClientError as error:
        log.debug(error)
        log.error('Failed to create ALB {0}: {1}: {2}'.format(name,
                                                              error.response['Error']['Code'],
                                                              error.response['Error']['Message']))


def delete(name,
           region=None,
           key=None,
           keyid=None,
           profile=None):

    '''
    .. versionadded:: XXXX.XX.XX

    Delete application load balancer.

    name
        (string) - application load balancer name or Amazon Resource Name (ARN).

    returns
        (bool) - True on success, False on failure.

    CLI examples:

    .. code-block:: bash

        salt myminion boto_elbv2.delete arn:aws:elasticloadbalancing:us-west-2:644138682826:loadbalancer/learn1give1-api/414788a16b5cf163
        salt myminion boto_elbv2.delete myExternalALB

    '''

    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)

    if not exists(name, region, key, keyid, profile):
        return True

    try:
        if name.startswith('arn:aws:elasticloadbalancing'):
            conn.delete_load_balancer(LoadBalancerArn=name)
            log.info('Deleted ALB {0}'.format(name))
        else:
            alb_info = conn.describe_load_balancers(Names=[name])
            if len(alb_info['LoadBalancers']) != 1:
                return False
            arn = alb_info['LoadBalancers'][0]['LoadBalancerArn']
            conn.delete_load_balancer(LoadBalancerArn=arn)
            log.info('Deleted ALB {0} ARN {1}'.format(name, arn))
        return True
    except ClientError as error:
        error_string = 'Failed to delete ALB {0}: {1}: {2}'.format(name,
                                                                   error.response['Error']['Code'],
                                                                   error.response['Error']['Message'])
        log.debug(error)
        log.error(error_string)
        return (False, error_string)


def exists(name,
           region=None,
           key=None,
           keyid=None,
           profile=None):

    '''
    .. versionadded:: XXXX.XX.XX

    Check to see if an application load balancer exists.

    CLI examples:

    .. code-block:: bash

        salt myminion boto_elbv2.load_balancer_exists arn:aws:elasticloadbalancing:us-west-2:644138682826:loadbalancer/myExternalALB/414788a16b5cf163
        salt myminion boto_elbv2.load_balancer_exists myExternalALB
    '''
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
    try:
        if name.startswith('arn:aws:elasticloadbalancing'):
            alb = conn.describe_load_balancers(LoadBalancerArns=[name])
        else:
            alb = conn.describe_load_balancers(Names=[name])
        if alb:
            return True
        else:
            log.warning('The application load balancer does not exist in region {0}'.format(region))
            return False
    except ClientError as error:
        log.warning('load_balancers_exists check for {0} returned: {1}'.format(name, error))
        return False


# TODO Add update_attributes so logging can be manipulated

def create_listener(lb_name,
                    protocol='HTTPS',
                    port=443,
                    ssl_policy=None,
                    cert_arn=None,
                    default_tg=None,
                    region=None,
                    key=None,
                    keyid=None,
                    profile=None):
    '''
    .. versionadded:: XXXX.XX.XX

    Create a listener for an aplication load balancer. Can be deleted by deleting
    the application load balancer.  Only one listener is allowed per port.

    lb_name
        (string) - The name of the application load balancer (ALB).
    protocol
        (string) - The protocol for the listener ( http | https )
    port
        (int) - The port to listen on.
    ssl_policy
        (string) - The security policy that defines which ciphers and protocols
                   are supported. The default is the current predefined security policy.
    cert_arn
        (string) - The certificate ARN ( AWS Certificate Manager ).
    default_tg
        (string) - The default target group name.

    returns
        (bool) - True on success, False on failure.

    CLI example:
    .. code-block:: bash

        salt myminion boto_elbv2.create_listener myExternalALB protocol=HTTPS port=443 \
        certificate=mySSLCert default_tg=myWebServers

    '''

    if not default_tg:
        return (False, 'default_tg must be specified')
    if protocol == 'HTTPS' and not cert_arn:
        return (False, 'certificate must be specified for HTTPS')

    if not exists(lb_name, region=region, key=key, keyid=keyid, profile=profile):
        return (False, 'Application load balancer {0} does not exist'.format(lb_name))

    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)

    lb_info = conn.describe_load_balancers(Names=[lb_name])
    if not lb_info:
        return (False, 'ALB {0} does not exist'.format(lb_name))

    lb_arn = lb_info['LoadBalancers'][0]['LoadBalancerArn']

    tg_arn = target_group_exists(default_tg, region, key, keyid, profile)
    if not tg_arn:
        return (False, 'Target group {0} does not exist'.format(default_tg))

    default_actions = {}
    default_actions['Type'] = 'forward'
    default_actions['TargetGroupArn'] = tg_arn

    certificates = {}
    certificates['CertificateArn'] = cert_arn

    if protocol not in ["HTTP", "HTTPS"]:
        return (False, 'Protocol {0} is not valid. Use http or https'.format(protocol))

    log.error('lb_arn {0}'.format(lb_arn))
    try:
        if ssl_policy:
            listener = conn.create_listener(LoadBalancerArn=lb_arn,
                                            Protocol=protocol,
                                            Port=port,
                                            SslPolicy=ssl_policy,
                                            Certificates=[certificates],
                                            DefaultActions=[default_actions])
        else:
            listener = conn.create_listener(LoadBalancerArn=lb_arn,
                                            Protocol=protocol,
                                            Port=port,
                                            Certificates=[certificates],
                                            DefaultActions=[default_actions])

        listener_string = '{0}:{1}:{2}'.format(lb_name, protocol, port)
        if listener:
            log.info('Created listener')
            return (True, 'Created listener {0}'.format(listener_string))
        else:
            log.error('Failed to create listener {0}'.format(listener_string))
            return (False, 'Failed to create listener {0}'.format(listenr_string))
    except ClientError as error:
        log.debug(error)
        log.error('Failed to create listener {0}  {1}:{2}'.format(listener_string,
                                                                  error.response['Error']['Code'],
                                                                  error.response['Error']['Message']))


def create_rule(lb_name,
                protocol,
                port,
                condition_type,
                condition_value,
                priority,
                target_group,
                region=None,
                key=None,
                keyid=None,
                profile=None):

    '''
    .. versionadded:: XXXX.XX.XX

    Create a listener rule.

    lb_name
        (string) - The name of the application load balancer (ALB).
    protocol
        (string) - The protocol for the listener ( HTTP | HTTPS )
    port
        (int) - The port to listen on.
    condition_type
        (string) - contition type ( ``host-header`` or ``path-pattern`` )
    condition_value
        (string) - contition value. For type host_header a case insensitive dns
                   hostname.  For path_pattern a case sensitive pattern to match
                   the URL path.  Can use wildcards like . * ?
    priority
        (int) - The priority for the rule. A listener can't have multiple rules
                with the same priority.
    target_group
        (string) - target group to forward traffic to if rule matches.

    returns
        (bool) - True on success, False on failure.

    CLI example:
    .. code-block:: bash

        salt myminion boto_elbv2.create_rule myExternalALB protocol=HTTPS port=443 \
        condition_type=path-pattern contition_value=/myapp target_group=myAppTargetGroup

    '''

    if not exists(lb_name, region, key, keyid, profile):
        return (False, 'Application load balancer {0} does not exist'.format(lb_name))

    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)

    lb_info = conn.describe_load_balancers(Names=[lb_name])
    if not lb_info:
        return (False, 'ALB {0} does not exist'.format(lb_name))
    lb_arn = lb_info['LoadBalancers'][0]['LoadBalancerArn']

    tg_arn = target_group_exists(target_group, region, key, keyid, profile)
    if not tg_arn:
        return (False, 'Target group {0} does not exist'.format(target_group))

    listener_info = conn.describe_listeners(LoadBalancerArn=lb_arn)
    if not listener_info:
        return (False, 'Listeners for {0} do not exist'.format(lb_name))

    listener_arn = False
    for listener in listener_info['Listeners']:
        log.error('port {0} protcol {1} arn {2}'.format(listener['Port'],
                                                        listener['Protocol'],
                                                        listener['ListenerArn']))
        if (listener['Port'] == port) and (listener['Protocol'] == protocol.upper()):
            listener_arn = listener['ListenerArn']
    if not listener_arn:
        return (False, 'Listener for {0} port {1} does not exist'.format(protocol, port))

    conditions = {}
    conditions['Field'] = condition_type
    conditions['Values'] = [condition_value]
    actions = {}
    actions['TargetGroupArn'] = tg_arn
    actions['Type'] = 'forward'
    rule_string = '{0} {1}'.format(condition_type, condition_value)

    try:
        rule = conn.create_rule(ListenerArn=listener_arn,
                                Conditions=[conditions],
                                Actions=[actions],
                                Priority=priority)
        if rule:
            return (True, 'Created rule {0}'.format(rule_string))
        else:
            log.error('Failed to create rule  {0}'.format(rule_string))
            return (False, 'Failed to create listener {0}'.format(rule_string))
    except ClientError as error:
        error_string = 'Failed to create rule "{0}". {1}:{2}'.format(rule_string,
                                                                     error.response['Error']['Code'],
                                                                     error.response['Error']['Message'])
        log.debug(error)
        log.error(error_string)
        return(False, error_string)


def delete_rule(lb_name,
                protocol,
                port,
                condition_type,
                condition_value):
    ''''
    .. versionadded:: XXXX.XX.XX

    Delete a Listener rule.

    lb_name
        (string) - The name of the application load balancer (ALB).
    protocol
        (string) - The protocol for the listener ( http | https )
    port
        (int) - The port to listen on.
    condition_type
        (string) - contition type ( ``host-header`` or ``path-pattern`` )
    condition_value
        (string) - contition value. For type host_header a case insensitive dns
                   hostname.  For path_pattern a case sensitive pattern to match
                   the URL path.  Can use wildcards like . * ?

    returns
        (bool) - True on success, False on failure.
    '''

    lb_info = conn.describe_load_balancers(Names=[lb_name])
    if not lb_info:
        return (False, 'ALB {0} does not exist'.format(lb_name))
    lb_arn = lb_info['LoadBalancers'][0]['LoadBalancerArn']

    listener_info = conn.describe_listeners(LoadBalancerArn=lb_arn)
    if not listener_info:
        return (False, 'Listeners for {0} do not exist'.format(lb_name))

    listener_arn = False
    for listener in listener_info['Listeners']:
        if (listener['Port'] == port) and (listener['Protocol'] == protocol):
            listener_arn = listener['ListenerArn']
            listener_name = listener['ListenerName']
    if not listener_arn:
        return (False, 'Listener for {0} port {1} does not exist'.format(protocol, port))

    rule_string = '{0} {1}'.format(condition_type, condition_value)
    rule_info = conn.describe_rules(ListenerArn=listener_arn)
    if not rule_info:
        return (False, 'Rules for listener {0} do not exist'.format(listener_name))
    for rule in rule_info['Rules']:
        if (rule['Conditions']['Field'] == condition_type) and (rule['Conditions']['Values'][0] == condition_value):
            rule_arn = rule['RuleArn']
    if not rule_arn:
        return (False, 'Rule matching "{0}" does not exist'.format(rule_string))

    try:
        if conn.delete_rule(RuleArn=rule_arn):
            return (True, 'Deleted rule {0}'.format(rule_string))
        else:
            log.error('Failed to create rule  "{0}"'.format(rule_string))
            return (False, 'Failed to create listener {0}'.format(rule_string))
    except ClientError as error:
        error_string = 'Failed to delete rule "{0}". {1}:{2}'.format(rule_string,
                                                                     error.response['Error']['Code'],
                                                                     error.response['Error']['Message'])
        log.debug(error)
        log.error(error_string)
        return (Falise, error_string)


def create_target_group(name,
                        protocol,
                        port,
                        vpc,
                        region=None,
                        key=None,
                        keyid=None,
                        profile=None,
                        health_check_protocol='HTTP',
                        health_check_port='traffic-port',
                        health_check_path='/',
                        health_check_interval_seconds=30,
                        health_check_timeout_seconds=5,
                        healthy_threshold_count=5,
                        unhealthy_threshold_count=2):
    '''
    .. versionadded:: XXXX.XX.XX

    Create target group if not present.

    name
        (string) - The name of the target group.
    protocol
        (string) - The protocol to use for routing traffic to the targets
    port
        (int) - The port on which the targets receive traffic. This port is used unless
        you specify a port override when registering the traffic.
    vpc
        (string) - The name or identifier of the virtual private cloud (VPC).
    health_check_protocol
        (string) - The protocol the load balancer uses when performing health check on
        targets. The default is the HTTP protocol.
    health_check_port
        (string) - The port the load balancer uses when performing health checks on
        targets. The default is 'traffic-port', which indicates the port on which each
        target receives traffic from the load balancer.
    health_check_path
        (string) - The ping path that is the destination on the targets for health
        checks. The default is /.
    health_check_interval_seconds
        (integer) - The approximate amount of time, in seconds, between health checks
        of an individual target. The default is 30 seconds.
    health_check_timeout_seconds
        (integer) - The amount of time, in seconds, during which no response from a
        target means a failed health check. The default is 5 seconds.
    healthy_threshold_count
        (integer) - The number of consecutive health checks successes required before
        considering an unhealthy target healthy. The default is 5.
    unhealthy_threshold_count
        (integer) - The number of consecutive health check failures required before
        considering a target unhealthy. The default is 2.

    returns
        (bool) - True on success, False on failure.

    CLI example:
    .. code-block:: bash

        salt myminion boto_elbv2.create_target_group learn1give1 protocol=HTTP port=54006 vpc_id=vpc-deadbeef
    '''

    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)

    if target_group_exists(name, region, key, keyid, profile):
        return (True, 'Target group {0} already exists'.format(name))

    vpc_id = __salt__['boto_vpc.check_vpc'](vpc_name=vpc,
                                            region=region,
                                            key=key,
                                            keyid=keyid,
                                            profile=profile)
    if not vpc_id:
        vpc_id = __salt__['boto_vpc.check_vpc'](vpc_id=vpc,
                                                region=region,
                                                key=key,
                                                keyid=keyid,
                                                profile=profile)
        if not vpc_id:
            return (False, 'VPC {0} does not exist'.format(vpc))

    try:
        alb = conn.create_target_group(Name=name,
                                       Protocol=protocol.upper(),
                                       Port=port,
                                       VpcId=vpc_id,
                                       HealthCheckProtocol=health_check_protocol,
                                       HealthCheckPort=health_check_port,
                                       HealthCheckPath=health_check_path,
                                       HealthCheckIntervalSeconds=health_check_interval_seconds,
                                       HealthCheckTimeoutSeconds=health_check_timeout_seconds,
                                       HealthyThresholdCount=healthy_threshold_count,
                                       UnhealthyThresholdCount=unhealthy_threshold_count)
        if alb:
            log.info('Created ALB {0}: {1}'.format(name,
                                                   alb['TargetGroups'][0]['TargetGroupArn']))
            return True
        else:
            log.error('Failed to create ALB {0}'.format(name))
            return (False, 'Failed to create ALB {0}'.format(name))
    except ClientError as error:
        error_string = 'Failed to create ALB {0}: {1}: {2}'.format(name,
                                                                   error.response['Error']['Code'],
                                                                   error.response['Error']['Message'])
        log.debug(error)
        log.error(error_string)
        return (False, error_string)

# TODO add update_target_group ( so healthcheck can be manipulated )


def delete_target_group(name,
                        region=None,
                        key=None,
                        keyid=None,
                        profile=None):
    '''
    .. versionadded:: XXXX.XX.XX

    Delete target group.

    name
        (string) - Target Group Name or Amazon Resource Name (ARN).

    returns
        (bool) - True on success, False on failure.

    CLI example:

    .. code-block:: bash

        salt myminion boto_elbv2.delete_target_group arn:aws:elasticloadbalancing:us-west-2:644138682826:targetgroup/learn1give1-api/414788a16b5cf163
    '''
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)

    if not target_group_exists(name, region, key, keyid, profile):
        return True

    try:
        if name.startswith('arn:aws:elasticloadbalancing'):
            conn.delete_target_group(TargetGroupArn=name)
            log.info('Deleted target group {0}'.format(name))
        else:
            tg_info = conn.describe_target_groups(Names=[name])
            if len(tg_info['TargetGroups']) != 1:
                return False
            arn = tg_info['TargetGroups'][0]['TargetGroupArn']
            conn.delete_target_group(TargetGroupArn=arn)
            log.info('Deleted target group {0} ARN {1}'.format(name, arn))
        return True
    except ClientError as error:
        error_string = 'Failed to delete target group {0}: {1}: {2}'.format(name,
                                                                            error.response['Error']['Code'],
                                                                            error.response['Error']['Message'])
        log.debug(error)
        log.error(error_string)
        return (False, error_string)


def target_group_exists(name,
                        region=None,
                        key=None,
                        keyid=None,
                        profile=None):
    '''
    .. versionadded:: 2017.7.0

    Check to see if an target group exists. returns the target group ARN

    CLI example:

    .. code-block:: bash

        salt myminion boto_elbv2.target_group_exists arn:aws:elasticloadbalancing:us-west-2:644138682826:targetgroup/learn1give1-api/414788a16b5cf163
    '''

    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        if name.startswith('arn:aws:elasticloadbalancing'):
            alb = conn.describe_target_groups(TargetGroupArns=[name])
        else:
            alb = conn.describe_target_groups(Names=[name])
        if alb:
            return alb['TargetGroups'][0]['TargetGroupArn']
        else:
            return False
    except ClientError as error:
        log.warning('target_group_exists check for {0} returned {1}'.format(name, error))
        return False


def describe_target_health(name,
                           targets=None,
                           region=None,
                           key=None,
                           keyid=None,
                           profile=None):
    '''
    .. versionadded:: 2017.7.0

    Get the curret health check status for targets in a target group.

    CLI example:

    .. code-block:: bash

        salt myminion boto_elbv2.describe_target_health arn:aws:elasticloadbalancing:us-west-2:644138682826:targetgroup/learn1give1-api/414788a16b5cf163 targets=["i-isdf23ifjf"]
    '''
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)

    try:
        if targets:
            targetsdict = []
            for target in targets:
                targetsdict.append({"Id": target})
            instances = conn.describe_target_health(TargetGroupArn=name,
                                                    Targets=targetsdict)
        else:
            instances = conn.describe_target_health(TargetGroupArn=name)
        ret = {}
        for instance in instances['TargetHealthDescriptions']:
            ret.update({instance['Target']['Id']: instance['TargetHealth']['State']})

        return ret
    except ClientError as error:
        log.warning(error)
        return {}


def register_targets(name,
                     targets,
                     region=None,
                     key=None,
                     keyid=None,
                     profile=None):
    '''
    .. versionadded:: 2017.7.0

    Register targets to a target froup of an ALB. ``targets`` is either a
    instance id string or a list of instance id's.

    Returns:

    - ``True``: instance(s) registered successfully
    - ``False``: instance(s) failed to be registered

    CLI example:

    .. code-block:: bash

        salt myminion boto_elbv2.register_targets myelb instance_id
        salt myminion boto_elbv2.register_targets myelb "[instance_id,instance_id]"
    '''
    targetsdict = []
    if isinstance(targets, six.string_types) or isinstance(targets, six.text_type):
        targetsdict.append({"Id": targets})
    else:
        for target in targets:
            targetsdict.append({"Id": target})
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)

    try:
        registered_targets = conn.register_targets(TargetGroupArn=name,
                                                   Targets=targetsdict)
        if registered_targets:
            return True
        return False
    except ClientError as error:
        log.warning(error)
        return False


def deregister_targets(name,
                       targets,
                       region=None,
                       key=None,
                       keyid=None,
                       profile=None):
    '''
    .. versionadded:: 2017.7.0

    Deregister targets to a target froup of an ALB. ``targets`` is either a
    instance id string or a list of instance id's.

    Returns:

    - ``True``: instance(s) deregistered successfully
    - ``False``: instance(s) failed to be deregistered

    CLI example:

    .. code-block:: bash

        salt myminion boto_elbv2.deregister_targets myelb instance_id
        salt myminion boto_elbv2.deregister_targets myelb "[instance_id,instance_id]"
    '''
    targetsdict = []
    if isinstance(targets, six.string_types) or isinstance(targets, six.text_type):
        targetsdict.append({"Id": targets})
    else:
        for target in targets:
            targetsdict.append({"Id": target})
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)

    try:
        registered_targets = conn.deregister_targets(TargetGroupArn=name,
                                                     Targets=targetsdict)
        if registered_targets:
            return True
        return False
    except ClientError as error:
        log.warning(error)
        return False
