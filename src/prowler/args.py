#  Copyright (c) 2020 nalansitan.
#  All rights reserved.

import getopt
import sys


def print_help():
    print('''USAGE:
      prowler [ -p <profile> -r <region>  -h ]
  Options:
      -p/--profile <profile>        specify your AWS profile to use (i.e.: default)
      -r/--region <region>         specify an AWS region to direct API requests to
                            (i.e.: us-east-1), all regions are checked anyway if the check requires it
      -c <check_id>       specify one or multiple check ids separated by commas, to see all available checks use -l option
                            (i.e.: check11 for check 1.1 or extra71,extra72 for extra check 71 and extra check 72)
      -g <group_id>       specify a group of checks by id, to see all available group of checks use -L
                            (i.e.: check3 for entire section 3, level1 for CIS Level 1 Profile Definitions or forensics-ready)
      -f <filterregion>   specify an AWS region to run checks against
                            (i.e.: us-west-1)
      -m <maxitems>       specify the maximum number of items to return for long-running requests (default: 100)
      -M <mode>           output mode: text (default), mono, json, json-asff, junit-xml, csv. They can be used combined comma separated.
                            (separator is ,; data is on stdout; progress on stderr).
      -k                  keep the credential report
      -n                  show check numbers to sort easier
                            (i.e.: 1.01 instead of 1.1)
      -l                  list all available checks only (does not perform any check). Add -g <group_id> to only list checks within the specified group
      -L                  list all groups (does not perform any check)
      -e                  exclude group extras
      -E                  execute all tests except a list of specified checks separated by comma (i.e. check21,check31)
      -b                  do not print Prowler banner
      -V                  show version number & exit
      -s                  show scoring report
      -S                  send check output to AWS Security Hub - only valid when the output mode is json-asff (i.e. -M json-asff -S)
      -x                  specify external directory with custom checks (i.e. /my/own/checks, files must start by check)
      -q                  suppress info messages and passing test output
      -A                  account id for the account where to assume a role, requires -R and -T
                            (i.e.: 123456789012)
      -R                  role name to assume in the account, requires -A and -T
                            (i.e.: ProwlerRole)
      -T                  session duration given to that role credentials in seconds, default 1h (3600) recommended 12h, requires -R and -T
                            (i.e.: 43200)
      -I                  External ID to be used when assuming roles (not mandatory), requires -A and -R.
      -h                  this help
    ''')


def get_argv(argv):
    result = {}
    try:
        opts, args = getopt.getopt(argv, "hp:r:", ["profile=", "region="])
    except getopt.GetoptError:
        print_help()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_help()
            sys.exit()
        elif opt in ("-p", "--profile"):
            result['profile'] = arg
        elif opt in ("-r", "--region"):
            result['region'] = arg
    return result

