#  Copyright (c) 2020 nalansitan.
#  All rights reserved.

from sys import stderr

from prowler.checks.IAMCheck import IAMCheck
from prowler.globals import Session


def main():
    print("python version of prowler, continually updated...", file=stderr)
    for rule in IAMCheck().rules():
        Session.check(rule)


if __name__ == '__main__':
    main()
