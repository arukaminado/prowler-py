#  Copyright (c) 2020 nalansitan.
#  All rights reserved.

from prowler.settings import aws_session
from prowler.checks import MFACheck

name = 'prowler'
__author__ = 'nalansitan'
__version__ = '0.0.1'


def main():
    print("python version of prowler, continually updated...")
    sts = aws_session.client('sts')
    response = sts.get_caller_identity()
    print(response)
    mfa_check = MFACheck().rules()
    print(mfa_check)
    # for check in mfa_check:
    #     print(check.check_function())


# debug
if __name__ == '__main__':
    main()

