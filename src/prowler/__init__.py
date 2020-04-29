#  Copyright (c) 2020 nalansitan.
#  All rights reserved.

from prowler.settings import aws_session
from prowler.checks.MFACheck import check_iam_mfa_for_users_with_console_password

name = 'prowler'
__author__ = 'nalansitan'
__version__ = '0.0.1'


def main():
    print("python version of prowler, continually updated...")
    # sts = aws_session.client('sts')
    # response = sts.get_caller_identity()
    # print(response)
    print(check_iam_mfa_for_users_with_console_password())


# debug
if __name__ == '__main__':
    main()

