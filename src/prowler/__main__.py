#  Copyright (c) 2020 nalansitan.
#  All rights reserved.

from prowler.checks.IAMCheck import IAMCheck
# from prowler.common.functions import *
from prowler.settings import aws_session


def main():
    print("python version of prowler, continually updated...")
    sts = aws_session.client('sts')
    # credential_report = get_credential_report()
    print(IAMCheck().rules())
    for rule in IAMCheck().rules():
        print('check %s : %s' % (rule.prowler_id, rule.title))
        print(rule.check_function())


if __name__ == '__main__':
    main()
