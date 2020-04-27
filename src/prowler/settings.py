#  Copyright (c) 2020 nalansitan.
#  All rights reserved.

import sys
import getopt
import boto3


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


args = get_argv(sys.argv[1:])
aws_session = boto3.session.Session(profile_name=args['profile'])