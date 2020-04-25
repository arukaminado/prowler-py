#  Copyright (c) 2020 nalansitan.
#  All rights reserved.

import sys, getopt
import boto3

name = 'prowler'
__author__ = 'nalansitan'
__version__ = '0.0.1'


def main():
    args = get_argv(sys.argv[1:])
    boto3.setup_default_session(profile_name=args['profile'])
    print("python version of prowler, continually updated...")
    sts = boto3.client('sts')
    response = sts.get_caller_identity()
    print(response)


def print_help():
    print('prowler -p <AWS_PROFILE>')


def get_argv(argv):
    result = {
        'profile': 'default',
    }
    try:
        opts, args = getopt.getopt(argv, "hp:", ["profile="])
    except getopt.GetoptError:
        print_help()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_help()
            sys.exit()
        elif opt in ("-p", "--profile"):
            result['profile'] = opt
    return result

