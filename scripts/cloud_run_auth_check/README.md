# Cloud Run authentication check

This check service tests Apps Script identity tokens and Cloud Run invoker authorization before
deploying the user-token service. Follow the public
[Cloud Run authentication check](../../docs/user-token-service.md#cloud-run-authentication-check)
for deployment steps and acceptance criteria.

From a test Sheet, use [`appsscript/appsscript.json`](appsscript/appsscript.json) for the required
scopes and [`appsscript/Code.gs`](appsscript/Code.gs) to log the identity-token audience and call
the check service. The service source is [`main.py`](main.py), with [`Procfile`](Procfile) for
startup.
