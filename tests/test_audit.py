import json
import logging

import pytest

from sg_token_broker._audit import AuditLogger


class TestAuditLogger:
    def test_default_logger_used_when_none_given(self, caplog: pytest.LogCaptureFixture) -> None:
        audit = AuditLogger()
        with caplog.at_level(logging.INFO, logger='sg_token_broker.audit'):
            audit.log('error', reason='upstream')
        assert json.loads(caplog.records[0].getMessage())['event'] == 'error'

    def test_emits_json_line(self, caplog: pytest.LogCaptureFixture) -> None:
        audit = AuditLogger(logging.getLogger('audit-test'))
        with caplog.at_level(logging.INFO, logger='audit-test'):
            audit.log('issue', client_id='farm', scope='read_all', cache='miss')
        record = json.loads(caplog.records[0].getMessage())
        assert record['event'] == 'issue'
        assert record['client_id'] == 'farm'
        assert 'ts' in record
