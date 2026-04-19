# Terms of Connection and Token Handling

> Draft only. Replace every bracketed placeholder before publishing. This document is a practical service draft, not legal advice.

## Publication Checklist

- Operator legal name: `[Operator Legal Name]`
- Support or privacy contact: `[Contact Email or URL]`
- Public service URL: `[Public Base URL]`
- Effective date: `[YYYY-MM-DD]`
- Governing law and venue: `[Jurisdiction]`
- Hosting region and infrastructure providers: `[Hosting Region and Providers]`
- Backup retention period: `[Retention Period]`
- Separate privacy notice URL, if any: `[Privacy Notice URL]`

## 1. Scope

These terms govern the use of the `edstem-mcp` service at the public URL identified above (the "Service"). The Service is a remote MCP server that, at a user's direction, uses that user's Ed Discussion API token to read from or write to the user's Ed Discussion account through MCP-compatible clients.

By connecting an MCP client, pasting an Ed API token, reconnecting Ed access, or using the Service, you agree to these terms.

If the operator later publishes a separate privacy notice, security notice, or acceptable use policy, those documents supplement these terms.

## 2. What the Service Does

The Service acts as a bridge between:

- your Ed Discussion account;
- your MCP client; and
- the operator's hosted MCP server runtime.

The Service does not replace Ed Discussion. It simply uses your authorization to make Ed API requests on your behalf and return the results to your MCP client.

Unless the operator explicitly states otherwise, the Service is independent from and not affiliated with Ed Discussion, your institution, or your MCP client vendor.

## 3. Definitions

- "Ed token" means the Ed Discussion API token you generate from your Ed account.
- "Ed account" means the Ed Discussion account identified by Ed when the Service verifies your Ed token.
- "Local account" means the Service-side user record linked to your verified Ed identity.
- "MCP client" means the external app or agent you connect to this Service.
- "Service OAuth token" means an authorization code, access token, refresh token, browser session cookie, or CSRF token issued by the Service for authentication or security purposes.
- "Write scope" means permission for the Service to perform Ed write actions on your behalf through supported tools.

## 4. Token Types and How They Differ

| Item | Issued by | Purpose | How this Service stores it | Linked to |
| --- | --- | --- | --- | --- |
| Ed token | You through Ed Discussion | Lets the Service call the Ed API as your Ed account | Encrypted at rest in the local database | One Local account and one Ed account |
| OAuth authorization code | The Service | One-time exchange step during MCP authorization | Stored in the local database until used or expired | Local account, client, scopes |
| OAuth access token | The Service | Lets the MCP client call this Service | Stored in the local database so the Service can validate requests and revoke or expire sessions | Local account, client, scopes |
| OAuth refresh token | The Service | Lets the MCP client obtain a new Service access token | Stored in the local database so the Service can refresh, revoke, and expire sessions | Local account, client, scopes |
| Browser session cookie | The Service | Keeps the browser authorization or settings session alive | Stored in your browser as a signed cookie and recognized by the Service | Browser session and Local account |
| CSRF token | The Service | Prevents cross-site request forgery on browser forms | Stored in your browser as a security cookie and form value | Browser session |

Important: the Ed token and the Service OAuth tokens are different credentials for different systems. Your MCP client receives Service OAuth tokens. It does not need your raw Ed token to call the Service, and the Service is not supposed to pass your Ed token through to the MCP client.

## 5. How the Service Handles Your Ed Token

The Service is designed to handle Ed tokens as follows:

1. You paste the Ed token into the authorization, settings, or reconnect form.
2. Before storing it, the Service verifies the token against Ed's `/api/user` endpoint.
3. If verification fails, the token is rejected and should not be stored.
4. If verification succeeds, the token is encrypted at rest using AES-256-GCM with the Service master key.
5. The database stores the encrypted token material plus limited metadata needed to operate the connection: Ed user ID, Ed user name, verification timestamp, invalidation flag, and record timestamps.
6. The plaintext token is intended to exist only transiently in process memory while being verified, used for an Ed API request, or re-encrypted during key rotation.
7. The Service is designed not to log plaintext Ed tokens or include them in user-facing error messages.

Current implementation detail: the encrypted Ed credential record contains ciphertext, IV, authentication tag, Ed user ID, Ed user name, `last_verified_at`, `is_invalid`, `created_at`, and `updated_at`.

## 6. Relationship Between Users, Ed Accounts, and Tokens

The Service treats token and user relationships as follows:

- one verified Ed token is treated as authority for the Ed account returned by Ed during verification;
- one Local account may hold one active Ed credential record at a time;
- the Local account is synced to the verified Ed identity returned by Ed, including Ed user ID and account email when available;
- a reconnect or token rotation is for the same Ed account only;
- if a new token belongs to a different Ed account, the Service may reject the update and require a new authorization flow or a fresh Local account;
- multiple MCP clients may hold separate Service OAuth tokens for the same Local account, but each token remains bound to the specific client, scopes, and expiry recorded by the Service.

This matters because the Service OAuth tokens authenticate a client to this Service, while the encrypted Ed token lets the Service act against Ed on behalf of the corresponding Ed account. They are linked, but they are not interchangeable.

## 7. What Data the Service Stores

Depending on how you use the Service, the operator may store:

- Local account data such as email, display name, Ed user ID, account creation time, and last login time;
- encrypted Ed credential records and the metadata described above;
- OAuth authorization codes, access tokens, refresh tokens, client IDs, scopes, redirect URIs, issuance timestamps, and expiry timestamps;
- browser session and CSRF cookies used for authorization, settings, reconnect, or account deletion flows;
- security and operational logs such as request IDs, client IP addresses, event names, user IDs, and serialized errors;
- database backups that may contain any of the items stored in the live database at the time of backup.

The Service is intended to collect and retain only what is needed to authenticate users, operate the Ed connection, enforce scopes, secure the Service, debug failures, and comply with reasonable operational or legal obligations.

## 8. Use of Your Data

The operator may use the data above to:

- verify that the Ed token belongs to a real Ed account;
- associate Service requests with the correct Local account and Ed account;
- authenticate and authorize MCP clients;
- enforce read and write scopes;
- return tool results to your MCP client;
- detect invalid credentials, abuse, or suspicious activity;
- maintain backups, restore the database after failures, and investigate incidents;
- comply with applicable law, lawful requests, or good-faith security obligations.

The Service is not supposed to sell your Ed token. The Service is also not supposed to use your Ed token for unrelated advertising, profiling, or data brokerage.

Automated decision-making in this Service is limited to operational checks such as token verification, scope enforcement, rate limiting, expiry handling, invalidation, and security controls.

## 9. Scopes, Permissions, and User Direction

The Service currently separates at least two permission levels:

- `mcp:tools.read` for read access; and
- `mcp:tools.write` for write operations.

By granting write scope, you authorize the Service to perform supported Ed write actions on your behalf through the connected MCP client. This may include submitting answers or other supported write operations. If you do not want write behavior, do not grant write scope.

You are responsible for the MCP clients you connect. If you authorize an untrusted client, that client may be able to use the Service within the scopes you granted.

## 10. Retention, Expiry, Revocation, and Deletion

The Service may retain data for as long as reasonably necessary to operate the connection, maintain security, support recovery, and satisfy legal obligations.

In practical terms:

- OAuth authorization codes may be deleted after use or expiry;
- Service access tokens and refresh tokens may remain until expiry, revocation, account deletion, or scheduled cleanup;
- browser sessions expire according to server configuration;
- an Ed credential may remain stored until you rotate it, delete the Local account, the operator deletes it, or the operator retires the Service;
- if Ed later rejects your token, the Service may mark the credential invalid and require reconnect instead of silently deleting it immediately;
- backups may preserve deleted data until the backup set ages out or is destroyed under the operator's retention schedule.

You may also revoke or regenerate your Ed token directly through Ed Discussion. Doing that may immediately or eventually break the Service connection until you reconnect with a fresh token.

If the Service provides a local account deletion flow, the Service is intended to remove the Local account, the encrypted Ed credential, the current browser session, and associated Service-issued OAuth records in the live database. Existing backups may survive longer.

## 11. Security Measures and Security Limits

The Service is intended to use reasonable technical controls, including:

- HTTPS in production;
- Ed token verification before storage;
- encrypted Ed token storage;
- scope enforcement for write actions;
- session cookies and CSRF protection on browser flows;
- rate limiting on sensitive endpoints; and
- log hygiene designed to avoid plaintext token disclosure.

No system is perfectly secure. You acknowledge the following real limits:

- if the Service database is compromised, metadata, logs, and Service OAuth tokens may be exposed;
- if both the encrypted database contents and the relevant master key are compromised, stored Ed tokens may become decryptable;
- if your MCP client, browser session, or device is compromised, an attacker may use valid Service tokens until they expire or are revoked;
- third-party services such as Ed Discussion, hosting providers, reverse proxies, or MCP clients may introduce independent security or privacy risks outside the operator's full control.

If you suspect compromise, you should revoke or regenerate your Ed token, disconnect or delete your Local account, and contact the operator immediately.

## 12. Backups and Disaster Recovery

The operator may create database backups for recovery purposes. Those backups can include:

- encrypted Ed credentials;
- Local account records;
- Service OAuth tokens and related metadata; and
- operational timestamps and linked identifiers.

Backups are operationally necessary, but they also widen the places where sensitive data can persist. The operator should protect backups with at least the same care as the live database.

## 13. Your Responsibilities

You agree that you will:

- connect only Ed accounts you own or are authorized to use;
- keep your Ed token, browser session, and MCP client credentials secure;
- grant write scope only when you actually want write behavior;
- review the actions of the MCP client you choose to connect;
- comply with Ed Discussion terms, your institution's rules, and applicable law;
- avoid uploading, requesting, or processing data through the Service when you lack authority to do so.

You must not:

- use the Service to impersonate other users without authorization;
- probe, abuse, overload, or interfere with the Service or Ed Discussion;
- try to bypass access controls, rate limits, or security mechanisms;
- use the Service for unlawful, fraudulent, or policy-violating conduct.

## 14. Third-Party Services and No Affiliation

Your use of the Service may involve third-party systems, including:

- Ed Discussion;
- your institution's Ed deployment or account policies;
- your chosen MCP client;
- the operator's hosting, logging, storage, CDN, reverse proxy, or backup providers.

Those third parties may have their own terms, retention rules, privacy notices, and security practices. The operator is not responsible for third-party outages, policy changes, account suspensions, or data handling outside the operator's own systems.

Unless expressly stated otherwise, the Service is not endorsed by or affiliated with Ed Discussion.

## 15. Suspension, Refusal, and Termination

The operator may suspend, limit, or terminate access to the Service if necessary to:

- protect the Service or other users;
- respond to abuse, fraud, legal complaints, or security incidents;
- perform maintenance or emergency remediation;
- retire features, clients, scopes, or the Service entirely.

The operator may also refuse connections or revoke Service-issued tokens when the operator reasonably believes continued access would create security, legal, or operational risk.

## 16. Disclaimers

The Service is provided on an "as is" and "as available" basis to the maximum extent permitted by law.

The operator does not guarantee:

- uninterrupted availability;
- compatibility with every MCP client;
- that Ed Discussion will remain stable, reachable, or API-compatible;
- that every write action will succeed, be reversible, or be suitable for your use case;
- that the Service will prevent every security incident, data loss event, or misuse by a client you authorized.

The Service is a bridge, not a promise that the world behaves.

## 17. Limitation of Liability

To the maximum extent permitted by law, the operator is not liable for indirect, incidental, special, consequential, exemplary, or punitive damages, or for loss of data, loss of access, loss of educational opportunity, loss of business, or client-side misuse arising from or related to the Service.

If the operator can legally limit direct liability, the operator's total liability should be capped at `[Liability Cap]` or the amount you paid for the Service in the preceding `[Period]`, whichever is greater, unless applicable law forbids that cap.

Nothing in these terms excludes liability that cannot legally be excluded.

## 18. Changes to These Terms

The operator may update these terms to reflect product changes, legal requirements, security changes, or operational reality. The updated version should identify a new effective date.

Material changes should be communicated through a reasonable channel such as the Service website, MCP authorization screen, repository, or operator contact channel.

## 19. Contact, Privacy Requests, and Complaints

Questions, deletion requests, security reports, and privacy inquiries should be sent to `[Contact Email or URL]`.

If the operator serves users in jurisdictions with privacy rights laws, the operator should also explain how users can request access, correction, deletion, objection, portability, or complaint handling, and under what limits those rights apply.

## 20. Operator Follow-Up Before Production Use

This draft is intentionally service-specific, but it still needs operator decisions before it is publishable:

- fill in the operator identity, contact channel, jurisdiction, hosting region, and retention schedule;
- decide whether a separate privacy notice is required for the deployment jurisdiction;
- confirm whether Service OAuth tokens will continue to be stored by token value or be redesigned later;
- document every infrastructure provider that can access logs, backups, or the database;
- make sure the public authorization page links to this document and any separate privacy notice;
- verify that backups, incident response, and deletion workflows match what this draft says.
