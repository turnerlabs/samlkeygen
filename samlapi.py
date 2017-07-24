#!/usr/bin/env python

"""
Prerequisites:
    - keyring ( optional )
    - argh
    - beautifulsoup4
    - requests-ntlm

This scripts authenticates you to your SAML provider and writes the
security token into the aws credentials file (~/.aws/credentials)

Heavily based on this blog post:
 - https://blogs.aws.amazon.com/security/post/Tx1LDN0UBGJJ26Q/How-to-Implement-Federated-API-and-CLI-Access-Using-SAML-2-0-and-AD-FS

 with some workarounds and lifting by myself

 Usage:
  ./aws_saml_access.py authenticate <adfs_url> --awsregion "us-east-1"
 or:
  ./aws-saml-access.py authenticate <adfs_url> -p dev_account --username \
      filipenf --role "arn:aws:iam::9999999:role/Dev-Role"

where <adfs_url> is
  https://<fqdn>/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices
"""

import boto.sts
import boto.s3
import requests
import getpass
import ConfigParser
import base64
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from os.path import expanduser
from requests_ntlm import HttpNtlmAuth
import logging
import argh
import os
from collections import namedtuple

OUTPUT_FORMAT = 'json'
AWS_CREDENTIALS_FILE = '/.aws/credentials'
AWS_ATTRIBUTE_ROLE = 'https://aws.amazon.com/SAML/Attributes/Role'
ATTRIBUTE_VALUE_URN = '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'

##########################################################################
def get_password(username):
    keyring_user = username.replace('\\', '-')
    try:
        import keyring
        password = keyring.get_password('samlauth', keyring_user)
        HAS_KEYRING=True
    except:
        HAS_KEYRING=False
        password = None
    if not password:
        password = getpass.getpass()
        if HAS_KEYRING:
            keyring.set_password('samlauth', keyring_user, password)
    return password

def ntlm_authenticate(adurl, sslverification, username):
    if not username:
        username = raw_input("Username: ")
    password = get_password(username)

    session = requests.Session()
    session.auth = HttpNtlmAuth(username, password, session)
    headers = {'User-Agent': 'Mozilla/5.0 (compatible, MSIE 11, "\
        "Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'}
    response = session.get(adurl, verify=sslverification, headers=headers)
    username = '##############################################'
    password = '##############################################'
    del username
    del password

    return response

def parse_response(response, desired_role, printroles):
    soup = BeautifulSoup(response.text, "html.parser")
    samlresponse = ''
    for inputtag in soup.find_all('input'):
        if inputtag.get('name') == 'SAMLResponse':
            samlresponse = inputtag.get('value')
    
    if not samlresponse:
        print "Error getting SAML Response. Please verify you have access to ADFS(which may require being VPN'd in)."
        exit(-1)
    
    roles = []
    role_tuple = namedtuple("RoleTuple", ["principal_arn", "role_arn"])
    root = ET.fromstring(base64.b64decode(samlresponse))
    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if saml2attribute.get('Name') == AWS_ATTRIBUTE_ROLE:
            for saml2attributevalue in saml2attribute.iter(ATTRIBUTE_VALUE_URN):
                roles.append(role_tuple(*saml2attributevalue.text.split(',')))

    #print ""
    selectedroleindex = -1

    if desired_role:
        desired = [r for r in roles if desired_role in r.role_arn]
        if len(desired) == 1:
            return (desired[0].role_arn, desired[0].principal_arn, samlresponse)
        else:
            print "The role %s does not exist in the provider. "\
                "Please verify" % desired_role

    #if --printroles is passed on cli, print list of roles and quit
    if printroles:
        for role in roles:
          print role.role_arn
        exit(0)

    if len(roles) == 1:
        selectedroleindex = 0

    while selectedroleindex < 0 or selectedroleindex > len(roles)-1:
        print "Please choose the role you would like to assume:"
        for i, role in enumerate(roles):
            print '[', i, ']: ', role.role_arn

        selectedroleindex = int(raw_input("Selection: "))

        if int(selectedroleindex) > (len(roles) - 1):
            logging.fatal('ERROR: You selected an invalid role index')

    selected_role = roles[selectedroleindex]

    return (selected_role.role_arn, selected_role.principal_arn, samlresponse)


def get_sts_token(role_arn, principal_arn, assertion, awsregion):
    conn = boto.sts.connect_to_region(awsregion)
    token = conn.assume_role_with_saml(role_arn, principal_arn, assertion)
    return token


def write_aws_credentials(token, profile_description, awsregion):
    home = expanduser("~")
    filename = home + AWS_CREDENTIALS_FILE
    config = ConfigParser.RawConfigParser()
    config.read(filename)
    if not config.has_section(profile_description):
        config.add_section(profile_description)
    config.set(profile_description, 'output', OUTPUT_FORMAT)
    config.set(profile_description, 'region', awsregion)
    config.set(profile_description, 'aws_access_key_id', token.credentials.access_key)
    config.set(profile_description, 'aws_secret_access_key', token.credentials.secret_key)
    config.set(profile_description, 'aws_session_token', token.credentials.session_token)
    config.set(profile_description, 'aws_security_token', token.credentials.session_token)

    with open(filename, 'w+') as configfile:
        config.write(configfile)

def create_default_section(aws_credentials_file, appendOrWriteFlag):
    # creates or appends to the credentials file with a default that will get immediately overlayed
    fhandle = open(aws_credentials_file, appendOrWriteFlag)
    fhandle.write("[default]")
    fhandle.write("\n")
    fhandle.write("region = us-east-1")
    fhandle.write("\n")
    fhandle.write("aws_access_key_id = xxxxxxxxxxxxxxxx")
    fhandle.write("\n")
    fhandle.write("aws_secret_access_key = xxxxxxxxxxxxxxxxx")
    fhandle.write("\n")
    fhandle.close()

def verify_default_section(aws_credentials_file):
    has_default = False
    has_region = False
    has_aws_access_key_id = False
    has_aws_secret_access_key = False

    # verifies that the default section exists along with the region, aws_access_key_id, and aws_secret_access_key
    with open(aws_credentials_file, 'r') as fhandle:
        for line in fhandle:
            if "default" in line:
                has_default = True
            if "region" in line:
                has_region = True
            if "aws_access_key_id" in line:
                has_aws_access_key_id = True
            if "aws_secret_access_key" in line:
                has_aws_secret_access_key = True
        fhandle.close()
        if has_default and has_region and has_aws_access_key_id and has_aws_secret_access_key:
            return True
        else:
            return False

def verify_credentials_file():
    home = expanduser("~")
    aws_credentials_directory = home + "/.aws"
    aws_credentials_file = home + AWS_CREDENTIALS_FILE

    try:
        os.stat(aws_credentials_directory)
        if os.path.exists(aws_credentials_file):
            if verify_default_section(aws_credentials_file):
                return
            else:
                create_default_section(aws_credentials_file, 'a')
        else:
            create_default_section(aws_credentials_file, 'w')
    except:
        os.mkdir(aws_credentials_directory)
        create_default_section(aws_credentials_file, 'w')


def authenticate(sslverification=True, profile_description="default", role=None, ntusername=None, awsregion="us-east-1", domain=None, printroles=False, adurl=None):
    if domain is None:
        print "Please include a domain with the command(ex. python samlapi.py authenticate --domain MyNTDomain)"
        exit()

    if adurl is None:
        print "Please include the active directory url with the command(ex. python samlapi.py authenticate --domain MyNTDomain -adurl http://adurl.com )"
        exit()

    if ntusername is None:
        print "Please include a username with the command(ex. python samlapi.py authenticate -n auser)"
        exit()

    username = domain + "\\" + ntusername

    "Authenticate with NTLM and saves the security token to your aws credentials file."

    if "?loginToRp=urn:amazon:webservices" not in adurl:
        logging.fatal("Wrong ADURL format. Please add ?loginToRp=urn:amazon:webservices to your ADURL")
        exit(-1)

    while not profile_description:
        profile_description = raw_input("Profile description: ")

    response = ntlm_authenticate(adurl, sslverification, username)

    (role_arn, principal_arn, assertion) = parse_response(response, role, printroles)

    verify_credentials_file()

    token = get_sts_token(role_arn, principal_arn, assertion, awsregion)

    write_aws_credentials(token, profile_description, awsregion)

    print '#\n#\n----------------------------------------------------------------'
    print '# Your new access key pair has been stored in the AWS configuration '\
          '# file %s%s under the %s profile.' % (expanduser("~"),
                                                AWS_CREDENTIALS_FILE,
                                                profile_description)
    print '# Note that it will expire at %s' % token.credentials.expiration
    print '# After this time you may safely rerun this script to refresh your '\
          '# access key pair.'
    print '# To use this credential call the AWS CLI with the --profile option '\
          '# (e.g. aws --profile default ec2 describe-instances).'
    print '#----------------------------------------------------------------\n#\n#'


if __name__ == "__main__":
    #logging.basicConfig(level=logging.DEBUG)
    argh.dispatch_commands([authenticate])
