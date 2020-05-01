#  Copyright (c) 2020 nalansitan.
#  All rights reserved.

import csv
import datetime
import io
import time
from functools import wraps
from typing import Callable

from prowler import g
from prowler.checks import CheckFunction
from prowler.settings import aws_session


def default_message(message='') -> Callable[[CheckFunction], CheckFunction]:
    def decorate(func: CheckFunction) -> CheckFunction:
        @wraps(func)
        def wrapped_func():
            ok, m = func()
            if ok and len(m) == 0 and len(message) != 0:
                m.append(message)
            return ok, m

        return wrapped_func

    return decorate


def get_credential_report():
    def actual_get_credential_report():
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
