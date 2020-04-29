#  Copyright (c) 2020 nalansitan.
#  All rights reserved.

import io
import csv
import time

from prowler.settings import aws_session


def get_credential_report():
    while True:
        response = aws_session.client('iam').generate_credential_report()
        if response['State'] == 'COMPLETE':
            break
        else:
            time.sleep(1)
    response = aws_session.client('iam').get_credential_report()
    assert response['ReportFormat'] == 'text/csv'
    csvfile = io.StringIO(response['Content'].decode('utf-8'))
    credential_report = list(csv.DictReader(csvfile))
    return credential_report

