import sys
from collections import defaultdict
from typing import Dict, List, Tuple

from termcolor import cprint

import boto3

from prowler.checks.AbstractCheck import Rule
from prowler.common.functions import lpad
from prowler.args import get_argv

g = defaultdict(lambda: None)

g['args'] = get_argv(sys.argv[1:])
g['aws_session'] = boto3.session.Session(profile_name=g['args'].get('profile'),
                                    region_name=g['args'].get('region'))


class Session(object):
    # Check ID, List of messages
    messages: Dict[str, List[Tuple[str, str]]] = {}
    current_check: Rule = None

    @classmethod
    def check(cls, rule: Rule):
        cls.current_check = rule
        if rule.rule_id not in cls.messages:
            cls.messages[rule.rule_id] = []
        cprint(lpad(rule.prowler_id, 7), 'cyan', end=' ')
        print(f'[{rule.rule_id}] {rule.title}')
        rule.check_function()

    @classmethod
    def log_pass(cls, text):
        cprint('   PASS ', 'green', attrs=['bold'], end='')
        print(text)
        cls.messages[cls.current_check.rule_id].append(('pass', text))

    @classmethod
    def log_info(cls, text):
        cprint('   INFO ', 'blue', attrs=['bold'], end='')
        print(text)
        cls.messages[cls.current_check.rule_id].append(('info', text))

    @classmethod
    def log_fail(cls, text):
        cprint('   FAIL ', 'red', attrs=['bold'], end='')
        print(text)
        cls.messages[cls.current_check.rule_id].append(('fail', text))
