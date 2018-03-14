# -*- coding: utf-8 -*-
'''
Connection module for Amazon SSM

:configuration: This module accepts explicit ssm credentials but can also
    utilize IAM roles assigned to the instance through Instance Profiles. Dynamic
    credentials are then automatically obtained from AWS API and no further
    configuration is necessary. More Information available at:

    .. code-block:: text

        http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html

    If IAM roles are not used you need to specify them either in a pillar or
    in the minion's config file:

    .. code-block:: yaml

        ssm.keyid: GKTADJGHEIQSXMKKRBJ08H
        ssm.key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs

    A region may also be specified in the configuration:

    .. code-block:: yaml

        ssm.region: us-east-1

    If a region is not specified, the default is us-east-1.

    It's also possible to specify key, keyid and region via a profile, either
    as a passed in dict, or as a string to pull from pillars or minion config:

    .. code-block:: yaml

        myprofile:
            keyid: GKTADJGHEIQSXMKKRBJ08H
            key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs
            region: us-east-1

:depends: boto3
'''
# keep lint from choking on _get_conn and _cache_id
#pylint: disable=E0602

# Import Python libs
from __future__ import absolute_import, print_function, unicode_literals
import logging

# Import Salt libs
import salt.utils.versions

log = logging.getLogger(__name__)

# Import third party libs
#pylint: disable=unused-import
try:
    import botocore
    import boto3
    import jmespath
    logging.getLogger('boto3').setLevel(logging.CRITICAL)
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False
#pylint: enable=unused-import

def _get_conn(key=None,
              keyid=None,
              profile=None,
              region=None,
              **kwargs):
    '''
    Create a boto3 client connection to SSM
    '''
    client = None
    if profile:
        if isinstance(profile, six.string_types):
            if profile in __pillar__:
                profile = __pillar__[profile]
            elif profile in __opts__:
                profile = __opts__[profile]
    elif key or keyid or region:
        profile = {}
        if key:
            profile['key'] = key
        if keyid:
            profile['keyid'] = keyid
        if region:
            profile['region'] = region

    if isinstance(profile, dict):
        if 'region' in profile:
            profile['region_name'] = profile['region']
            profile.pop('region', None)
        if 'key' in profile:
            profile['aws_secret_access_key'] = profile['key']
            profile.pop('key', None)
        if 'keyid' in profile:
            profile['aws_access_key_id'] = profile['keyid']
            profile.pop('keyid', None)

        client = boto3.client('ssm', **profile)
    else:
        client = boto3.client('ssm')

    return client

def __virtual__():
    '''
    Only load if boto libraries exist.
    '''
    has_boto_reqs = salt.utils.versions.check_boto_reqs()
    if has_boto_reqs is True:
        __utils__['boto3.assign_funcs'](__name__, 'ssm')
    return has_boto_reqs


def get_parameter(name, withdecryption=False, resp_json=False, region=None, key=None, keyid=None, profile=None):
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
    resp = conn.get_parameter(Name=name, WithDecryption=withdecryption)
    if resp_json:
        return json.loads(resp['Parameter']['Value'])
    else:
        return resp['Parameter']['Value']

def put_parameter(Name, Value, Description=None, Type='String', KeyId=None, Overwrite=False, AllowedPattern=None, region=None, key=None, keyid=None, profile=None):
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
    if Type not in ('String', 'StringList', 'SecureString'):
        raise BadOption('Type needs to be String|StringList|SecureString')
    if Type is 'SecureString' and not KeyId:
        raise RequiredOption('Require KeyId with SecureString')
    resp = conn.put_parameter(Name=Name)
    return resp['Version']

def delete_parameter(Name, region=None, key=None, keyid=None, profile=None):
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
    resp = conn.delete_parameter(Name=Name)
    return True
