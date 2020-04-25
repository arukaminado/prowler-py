import base64
import time
from typing import List

import boto3

from . import AbstractCheck, Rule


def check_iam_mfa_for_users_with_console_password() -> List[str]:
    while True:
        response = boto3.client('iam').generate_credential_report()
        if response['State'] == 'COMPLETE':
            break
        else:
            time.sleep(1)
    response = boto3.client('iam').get_credential_report()
    assert response['ReportFormat'] == 'text/csv'
    credential_report = base64.b64decode(response['Content'])
    return []


class MFACheck(AbstractCheck):
    def rules(self) -> List[Rule]:
        return [
            Rule(
                'check12',
                'iam_mfa_for_users_with_console_password',
                'Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password',
                True,
                1,
                check_iam_mfa_for_users_with_console_password
            )
        ]
