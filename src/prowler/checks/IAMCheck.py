from importlib import import_module
from typing import Tuple, List

import yaml

from prowler.common.functions import *
from . import AbstractCheck, Rule


@default_message('Root user in the account has not been accessed in the last 1 day.')
def check_iam_root_disabled() -> Tuple[bool, List[str]]:
    credential_report = get_credential_report()
    result = []
    root_user = [user for user in credential_report if user.get('user') == '<root_account>']
    if root_user:
        if calculate_days(root_user[-1].get('password_last_used')) <= 1:
            result.append('Root user in the account was last accessed 1 day ago using password.')
        if calculate_days(root_user[-1].get('access_key_1_last_used_date')) <= 1:
            result.append('Root user in the account was last accessed 1 day ago using access key.')
        if calculate_days(root_user[-1].get('access_key_2_last_used_date')) <= 1:
            result.append('Root user in the account was last accessed 1 day ago using access key.')
    return len(result) == 0, result


@default_message('No users found with Password enabled and MFA disabled')
def check_iam_mfa_for_users_with_console_password() -> Tuple[bool, List[str]]:
    credential_report = get_credential_report()
    result = []
    for user in credential_report:
        if user.get('password_enabled') == 'true' and user.get('mfa_active') == 'false':
            result.append('User' + user + ' has Password enabled but MFA disabled')
    return len(result) == 0, result


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
