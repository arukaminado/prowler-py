#  Copyright (c) 2020 nalansitan.
#  All rights reserved.

import csv
import datetime
import io
import time


def get_credential_report():
    from prowler.globals import g

    def actual_get_credential_report():
        while True:
            response = g['aws_session'].client('iam').generate_credential_report()
            if response['State'] == 'COMPLETE':
                break
            else:
                time.sleep(1)
        response = g['aws_session'].client('iam').get_credential_report()
        assert response['ReportFormat'] == 'text/csv'
        csvfile = io.StringIO(response['Content'].decode('utf-8'))
        credential_report = list(csv.DictReader(csvfile))
        return credential_report

    report = g['credential_report']
    if not report:
        report = actual_get_credential_report()
        g['credential_report'] = report
    return report


def calculate_days(iso_time):
    try:
        now = datetime.datetime.now(datetime.timezone.utc)
        delta = now - datetime.datetime.fromisoformat(iso_time)
        return delta.days
    except Exception as e:
        return 999999


def lpad(s, l):
    return ' ' * (l - len(s)) + s
