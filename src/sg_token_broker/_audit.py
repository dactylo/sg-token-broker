"""Emit structured audit events as JSON lines."""

import datetime
import json
import logging

from sg_token_broker._servicelog import ServiceWriter

_AUDIT_LOGGER_NAME = 'sg_token_broker.audit'


class AuditLogger:
    """Write audit events as JSON lines via standard logging."""

    def __init__(self, logger: logging.Logger | ServiceWriter | None = None) -> None:
        """Select the logger that receives structured audit events.

        Args:
            logger: Destination logger. Defaults to `sg_token_broker.audit`.
        """
        self._logger = logger if logger is not None else logging.getLogger(_AUDIT_LOGGER_NAME)

    def log(self, event: str, **fields: object) -> None:
        """Emit one audit event.

        Args:
            event: Event name (`issue`, `deny`, or `error`).
            **fields: Additional JSON-serializable context fields.
        """
        record: dict[str, object] = {
            'ts': datetime.datetime.now(datetime.UTC).isoformat(),
            **fields,
            'event': event,
        }
        # For issuance, denial and error (including parser rejections), both HTTP services
        # attempt this write and flush before the first byte of the final response. Healthy
        # probes, interim 100s and listener refusals have no audit. The sink owns retention.
        self._logger.log(logging.INFO, json.dumps(record, sort_keys=True, default=str))
