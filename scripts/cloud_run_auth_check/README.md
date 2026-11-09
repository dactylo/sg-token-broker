# Cloud Run authentication check

Use this helper before deploying the user-token service to check that Cloud Run accepts Apps Script
identity tokens and allows only your invoker group. It needs no SG key. Follow the
[deployment steps and expected results](../../docs/user-token-service.md#cloud-run-authentication-check).

The helper echoes identity claims and relies on Cloud Run IAM to verify the caller. Deploy it with
`--no-allow-unauthenticated`; it does not verify token signatures itself.

For the test Sheet, use these files:

| File                                                       | Purpose                                           |
| ---------------------------------------------------------- | ------------------------------------------------- |
| [`appsscript/appsscript.json`](appsscript/appsscript.json) | Required identity-token and request scopes        |
| [`appsscript/Code.gs`](appsscript/Code.gs)                 | Log the token audience and call the check service |
| [`main.py`](main.py)                                       | Check-service HTTP handler                        |
| [`Procfile`](Procfile)                                     | Service startup command                           |
