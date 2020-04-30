from typing import List

from . import AbstractCheck, Rule
from prowler.common.functions import *


def check_iam_mfa_for_users_with_console_password() -> List[str]:
    credential_report = get_credential_report()
    result = []
    for user in credential_report:
        if user['password_enabled'] == 'true' and user['mfa_active'] == 'false':
            result.append('User' + user + ' has Password enabled but MFA disabled')
    if not result:
        result.append('No users found with Password enabled and MFA disabled')
    return result


class MFACheck(AbstractCheck):
    def rules(self) -> List[Rule]:
        return [
            Rule(
                'check12',
                'iam_mfa_for_users_with_console_password',
                'Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password',
                True,
                1,
                True,
                check_iam_mfa_for_users_with_console_password
            )
        ]
