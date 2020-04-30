#  Copyright (c) 2020 nalansitan.
#  All rights reserved.

from prowler.checks.MFACheck import MFACheck
from prowler.settings import aws_session


def main():
    print("python version of prowler, continually updated...")
    sts = aws_session.client('sts')
    print(MFACheck().rules())


if __name__ == '__main__':
    main()
