from importlib import import_module
from typing import List

import yaml

from prowler import Session
from prowler.common.functions import get_credential_report, calculate_days
from . import AbstractCheck, Rule


def check_iam_root_disabled() -> None:
    credential_report = get_credential_report()
    root_user = [user for user in credential_report if user.get('user') == '<root_account>']
    Session.log_info('Test')
    success = True
    if root_user:
        if calculate_days(root_user[-1].get('password_last_used')) <= 1:
            Session.log_fail('Root user in the account was last accessed 1 day ago using password.')
            success = False
        if calculate_days(root_user[-1].get('access_key_1_last_used_date')) <= 1:
            Session.log_fail('Root user in the account was last accessed 1 day ago using access key.')
            success = False
        if calculate_days(root_user[-1].get('access_key_2_last_used_date')) <= 1:
            Session.log_fail('Root user in the account was last accessed 1 day ago using access key.')
            success = False
    if success:
        Session.log_pass('Root user in the account has not been accessed in the last 1 day.')


def check_iam_mfa_for_users_with_console_password() -> None:
    credential_report = get_credential_report()
    Session.log_info('Test')
    Session.log_fail('Test fail')
    success = True
    for user in credential_report:
        if user.get('password_enabled') == 'true' and user.get('mfa_active') == 'false':
            Session.log_fail('User' + user + ' has Password enabled but MFA disabled')
            success = False
    if success:
        Session.log_pass('No users found with Password enabled and MFA disabled')


class IAMCheck(AbstractCheck):
    def rules(self) -> List[Rule]:
        with open(self.checks_file()) as f:
            checks = yaml.load(f, Loader=yaml.Loader)['checks']
        rules: List[Rule] = []
        for check in checks:
            d = {}
            for field in Rule._fields:
                if field != 'check_function':
                    d[field] = check[field]
                else:
                    p, m = check[field].rsplit('.', 1)
                    module = import_module(p)
                    method = getattr(module, m)
                    d[field] = method
            rules.append(Rule(**d))
        return rules
