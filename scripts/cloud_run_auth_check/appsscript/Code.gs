// Cloud Run authentication check caller. Paste into a test Sheet's Apps Script
// project (with the sibling appsscript.json manifest), set SERVICE_URL, then
// run logIdentityAudience() first and checkServiceAccess() after deploying.

const SERVICE_URL = 'https://sg-token-auth-check-HASH.run.app';

// Logs the ID token's aud claim. Use that value as the Cloud Run custom
// audience (it is the script's OAuth client ID, not the service URL).
function logIdentityAudience() {
  const token = ScriptApp.getIdentityToken();
  const payload = Utilities.newBlob(
    Utilities.base64DecodeWebSafe(token.split('.')[1])
  ).getDataAsString();
  Logger.log(JSON.parse(payload).aud);
}

// Expect 200 + the caller's email for invoker-group members and 403 for a
// non-member. A 401 rejects the token and does not establish group rejection.
function checkServiceAccess() {
  const token = ScriptApp.getIdentityToken();
  const response = UrlFetchApp.fetch(SERVICE_URL, {
    headers: { Authorization: 'Bearer ' + token },
    muteHttpExceptions: true,
  });
  Logger.log(response.getResponseCode());
  Logger.log(response.getContentText());
}
