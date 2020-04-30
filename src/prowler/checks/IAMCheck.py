from importlib import import_module
from typing import List, Tuple

import yaml

from prowler.common.functions import *
from . import AbstractCheck, Rule


def check_iam_mfa_for_users_with_console_password() -> Tuple[bool, List[str]]:
    credential_report = get_credential_report()
    ok, result = True, []
    for user in credential_report:
        if user.get('password_enabled') == 'true' and user.get('mfa_active') == 'false':
            result.append('User' + user + ' has Password enabled but MFA disabled')
            ok = False
    if not result:
        result.append('No users found with Password enabled and MFA disabled')
        ok = True
    return ok, result


def check_iam_root_disabled() -> Tuple[bool, List[str]]:
    credential_report = get_credential_report()
    ok, result = True, []
    root_user = [user for user in credential_report if user.get('user') == '<root_account>']
    if root_user:
        if calculate_days(root_user[-1].get('password_last_used')) <= 1:
            ok = False
            result.append('Root user in the account was last accessed 1 day ago using password.')
        if calculate_days(root_user[-1].get('access_key_1_last_used_date')) <= 1:
            ok = False
            result.append('Root user in the account was last accessed 1 day ago using access key.')
        if calculate_days(root_user[-1].get('access_key_2_last_used_date')) <= 1:
            ok = False
            result.append('Root user in the account was last accessed 1 day ago using access key.')
        if ok:
            result.append('Root user in the account wasn\'t accessed in the last 1 day.')
    return ok, result


class IAMCheck(AbstractCheck):
    @staticmethod
    def checks_file() -> str:
        a = __file__.rsplit('.', 1)
        assert a[1] == 'py'
        return a[0] + '.yml'

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
