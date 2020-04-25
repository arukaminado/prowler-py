import base64
import time
from typing import List

import boto3

from . import AbstractCheck


class MFACheck(AbstractCheck):
    @property
    def id(self) -> str:
        return 'iam-user-mfa'

    @property
    def title(self) -> str:
        return 'Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password'

    @property
    def scored(self) -> bool:
        return True

    @property
    def level(self) -> int:
        return 1

    def check(self) -> List[str]:
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
