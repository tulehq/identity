# identity

An AWS IAM- and STS-compatible identity service that keeps users, access keys
and role sessions in a local SQLite database. It is built to stand in for IAM
and STS in local development and end-to-end tests: point an AWS SDK at it and
the usual user, access key, caller identity and AssumeRole calls work.

It also issues the keys the other Tule services verify. A service asks
identity's [signing-key endpoint](#the-signing-key-endpoint) for the SigV4
signing key of a request's credential and checks the signature itself, so a
key created here works against every Tule service.

It is not a production identity service. There are no policies: who may do
what is decided by the fixed rules [below](#principals-and-permissions), and
secrets are stored as they are.

## Running it

With Docker:

```sh
docker run --rm -p 9030:9030 -v identitydata:/data \
  -e TULE_Auth_AccessKeyID=AKIAIOSFODNN7EXAMPLE \
  -e TULE_Auth_SecretAccessKey=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  ghcr.io/tulehq/identity:latest
```

The image is based on Alpine, so `docker exec -it <container> sh` gives you a
shell. It runs as the unprivileged `nonroot` user, keeps its database at
`/data/identity.db` on the `/data` volume, and its Docker health check polls
`/_ready`.

From source (Go 1.27.4 or later):

```sh
make build
TULE_Auth_AccessKeyID=AKIAIOSFODNN7EXAMPLE \
TULE_Auth_SecretAccessKey=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  ./build/tule-identity
```

It listens on port 9030, so it does not collide with
[object-store](https://github.com/tulehq/object-store) on 9000,
[secret-store](https://github.com/tulehq/secret-store) on 9010 or
[accounts](https://github.com/tulehq/accounts) on 9020.

## Configuration

Settings come from environment variables prefixed with `TULE_`, and from a
`.env` file in the working directory (without the prefix).

| Variable | Default | Purpose |
|---|---|---|
| `TULE_Server_Port` | `9030` | Listen port |
| `TULE_Store_Path` | `./data/identity.db` (`/data/identity.db` in the image) | The SQLite database file; it and its directory are created if missing |
| `TULE_Auth_AccessKeyID` | required | The root user's access key ID, the key every Tule service is configured with |
| `TULE_Auth_SecretAccessKey` | required | Its secret |
| `TULE_Identity_AccountID` | `000000000000` | The management account, the root user's: 12 digits. The default is accounts' default management account |
| `TULE_Identity_AccountsEndpoint` | unset | The accounts service's base URL, such as `http://localhost:9020`, which `AssumeRole` asks about member accounts. Unset, no role can be assumed |
| `TULE_HSTS_MaxAge` | unset | `Strict-Transport-Security` max age; the header is only sent when set |
| `TULE_Server_ReadTimeout` | `30s` | How long the server may take to read a request, body included |
| `TULE_Server_ReadHeaderTimeout` | `30s` | How long it may take to read a request's headers; must be positive |
| `TULE_Server_WriteTimeout` | `30s` | How long it may take to write a response |
| `TULE_Server_IdleTimeout` | `2m` | How long a keep-alive connection may sit idle between requests |
| `TULE_Server_ShutdownTimeout` | `7s` | How long a graceful shutdown waits for in-flight requests |
| `TULE_GasEnv` | | `development` logs console output at trace level, `production` logs at warn level, `testing` disables logging |

The read and write timeouts are sized for a signed request body of up to 1 MiB,
which is the largest this service accepts. Logs go to the console only; there
is no log shipping.

The server refuses to start without the root user's key, because every request
is verified and any web page the developer has open can reach a server on
localhost. It also refuses an account ID that is not 12 digits and an accounts
endpoint that is not an `http` or `https` URL.

`GetAccessKeyInfo` takes an access key ID of at least 16 characters, so a
root key ID shorter than that, such as `test`, works for signing but cannot be
looked up. The AWS documentation's example key, used above, is 20.

## Health checks

`GET /_health` (liveness) and `GET /_ready` (readiness) answer without a
signature. They respond `200` when every service reports healthy or ready and
`503` otherwise, with a JSON object of each service's status. Readiness fails
when the database cannot be reached or its schema is not applied.

## Connecting a client

IAM and STS both speak the AWS Query protocol: a signed, form-encoded
`POST /` naming the operation in `Action` and the API version in `Version`,
answered in XML. One server serves both, and tells them apart by the service
the request's credential is scoped to, which the SDKs set from the client:
`iam` or `sts`. Point both clients at the same URL and sign for `us-east-1`.

Go (AWS SDK v2):

```go
creds := credentials.NewStaticCredentialsProvider(keyID, secret, "")
iamClient := iam.New(iam.Options{
	Region:       "us-east-1",
	BaseEndpoint: aws.String("http://localhost:9030"),
	Credentials:  creds,
})
stsClient := sts.New(sts.Options{
	Region:       "us-east-1",
	BaseEndpoint: aws.String("http://localhost:9030"),
	Credentials:  creds,
})
```

Or with `curl`, which signs requests too:

```sh
curl -fsS --aws-sigv4 aws:amz:us-east-1:iam \
  --user AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  --data-binary 'Action=CreateUser&Version=2010-05-08&UserName=dev' \
  http://localhost:9030/
```

## Supported operations

IAM (`2010-05-08`):

| Operation | Notes |
|---|---|
| `CreateUser` | `Path` defaults to `/`. Names are unique in the account without regard to case. Takes `Tags` |
| `GetUser` | With its tags. Without `UserName`, the caller: the root user for the root key |
| `ListUsers` | Filtered by `PathPrefix`, paginated with `Marker` and `MaxItems` |
| `DeleteUser` | Fails with `DeleteConflict` while the IAM user has access keys |
| `CreateAccessKey` | The only response that carries the secret. At most two keys per user, then `LimitExceeded` |
| `ListAccessKeys` | Paginated. Without `UserName`, the root key lists itself |
| `UpdateAccessKey` | `Active` or `Inactive` |
| `DeleteAccessKey` | |
| `GetAccessKeyLastUsed` | For a user's key or the root user's |
| `TagUser` / `UntagUser` | At most 50 tags on a user |
| `ListUserTags` | Paginated, in order of their keys |

STS (`2011-06-15`):

| Operation | Notes |
|---|---|
| `GetCallerIdentity` | Any active principal |
| `GetAccessKeyInfo` | The account of any key this service issued, the root user's included, whatever its status |
| `AssumeRole` | `OrganizationAccountAccessRole` only, below |

IDs have AWS's formats: `AIDA` and 17 base32 characters for a user (21 in
all), `AKIA` and 16 for an access key, `ASIA` and 16 for a role session's
key, `AROA` and 17 for the role, and a secret is 40 characters of the base64
alphabet. A user's ARN is `arn:aws:iam::<account>:user<path><name>`; a role
session's is
`arn:aws:sts::<account>:assumed-role/OrganizationAccountAccessRole/<session>`
and its `UserId` is `<role ID>:<session>`; the root user's is
`arn:aws:iam::<account>:root` and its `UserId` is the account ID.

Request parameters are checked against the lengths, patterns, ranges and
enumerations of the IAM and STS models, and a value that breaks one fails with
`ValidationError` in the Query services' message form ("1 validation error
detected: Value 'x' at 'userName' failed to satisfy constraint: ..."). A user
or key that does not exist is `NoSuchEntity`, a taken name
`EntityAlreadyExists`. `MaxItems` is 1 to 1000, 100 by default; `IsTruncated`
and `Marker` page as AWS's do, and the SDK paginators work.

Tags follow the IAM model and the IAM User Guide: a key of 1 to 128
characters and a value of 0 to 256, of letters, digits, spaces and
`_.:/=+-@`; at most 50 in a request and on a user, past which `TagUser`
fails with `LimitExceeded` and sets none; no key or value that begins with
`aws:`, which is `InvalidInput`. A user's tag keys are not case sensitive but
keep their case: tagging `env` on a user tagged `Env` replaces that tag, and
a request that names a key twice is `InvalidInput`.

## Principals and permissions

There are three kinds of principal:

- **The root user** of the management account: the configured key. It acts in
  `TULE_Identity_AccountID`.
- **IAM users** and their access keys. Each user belongs to one account.
- **Role sessions** from `AssumeRole`, with an access key, a secret, a session
  token and an expiration. A session acts in its role's account.

With no policies, the rules are fixed:

- The IAM operations may be called by an **admin principal** only: the root
  user, and `OrganizationAccountAccessRole` sessions. Each acts in its own
  account: users the root user creates are the management account's, users a
  session creates are its member account's. Anyone else, an IAM user, gets
  `AccessDenied` (`403`), "User: \<arn\> is not authorized to perform:
  iam:\<action\> on resource: \<arn\>".
- Every active principal may call `GetCallerIdentity` and `GetAccessKeyInfo`,
  and every active key works against the other Tule services.
- `AssumeRole` may be called by the root user only.

An inactive or deleted key, and a session's key without its token, are
refused with `InvalidClientTokenId`, as AWS refuses an invalid key; an expired
session's token with `ExpiredToken` (`403`).

### The root user

Called without `UserName`, IAM acts on the caller, and for the root key that
is the root user. `GetUser` returns it as the policy variables reference
describes it: its `UserId` is the account ID, its ARN
`arn:aws:iam::<account>:root`, and it has no user name or path.
`ListAccessKeys` lists its one key, the configured one, `Active`. Both report
as their `CreateDate` the time the database was created.

The root key is configured, not stored, so `CreateAccessKey`,
`UpdateAccessKey` and `DeleteAccessKey` without `UserName` under the root key
fail with `InvalidInput` (`400`), saying so; AWS would create, change or
delete a root access key. A role session must name a user: without
`UserName` these operations, `GetUser` and `ListAccessKeys` fail with
`ValidationError`, "Must specify userName when calling with non-User
credentials".

### AssumeRole

Only `arn:aws:iam::<account>:role/OrganizationAccountAccessRole` can be
assumed, where `<account>` is an `ACTIVE` member of the organization other
than the management account, by the root user. identity asks the accounts
service, with Organizations calls signed with the root user's key: which
account manages the organization (`DescribeOrganization`), and whether the
account is an active member (`DescribeAccount`). The management account
accounts reports must be `TULE_Identity_AccountID`, the root user's; when it
is not, `AssumeRole` fails with `500` `InternalFailure` naming both, and the
mismatch is logged, since no answer would be right. Any other role, account or caller, and
every role when no accounts endpoint is configured, is refused with
`AccessDenied`, as AWS refuses a role that does not exist.

`DurationSeconds` is 900 to 43200 by the model and defaults to 3600; more
than 3600, the maximum session duration of a role created with no other
setting, fails with `ValidationError`. The session expires then: its token is
refused with `ExpiredToken` from that moment.

## The signing-key endpoint

An internal endpoint, not an AWS API, that the other Tule services verify
requests through. It is `POST /_internal/signing-key`, which no Query request
uses, since those are all `POST /`.

- **Authentication.** A call is SigV4-signed with the root user's key, for the
  signing name `identity` in `us-east-1`. Anything else is refused, `403`
  with the sigv4 Kind as the code, before the body is read.
- **Request.** The credential scope of the request the caller wants to verify,
  as JSON:

  ```json
  {"AccessKeyId": "AKIA...", "SessionToken": "...", "Date": "20261113",
   "Region": "us-east-1", "Service": "secretsmanager"}
  ```

  `SessionToken` is left out when the request carries none.
- **Response.** `200` with the derived signing key for that date, region and
  service, base64-encoded, and the principal the key belongs to. It never
  returns a secret:

  ```json
  {"Principal": {"AccountId": "000000000000",
                 "Arn": "arn:aws:iam::000000000000:user/dev",
                 "AccessKeyId": "AKIA..."},
   "SigningKey": "..."}
  ```

- **Refusals.** `400` with a `Code` of `UnknownAccessKey` (unknown or deleted,
  or a session key without its token), `InactiveAccessKey`,
  `InvalidSessionToken` (not the key's token, or a token sent with a
  long-term key) or `ExpiredSessionToken` (the session's own token, past its
  expiration). A body that is not a scope is `400` `InvalidRequest`; a
  failure of the store is `500`.
- **Last use.** Each key handed out is recorded as used, with the scope's
  service and region, for `GetAccessKeyLastUsed`.

### The KeySource client

`tule.dev/identity/keysource` is a `tule.dev/sigv4` `KeySource` over the
endpoint:

```go
ks, err := keysource.New(keysource.Config{
	Endpoint:        "http://localhost:9030",
	AccessKeyID:     rootKeyID,
	SecretAccessKey: rootSecret,
})
v, err := sigv4.New(ks, sigv4.WithErrorMap(toAPIError))
```

It maps the refusals to `sigv4.ErrUnknownAccessKey`,
`sigv4.ErrInvalidSessionToken` and `sigv4.ErrExpiredSessionToken`, so a
verifier answers them as it answers its own; `InactiveAccessKey` becomes
`keysource.ErrInactiveAccessKey`, which wraps `sigv4.ErrUnknownAccessKey`. Any
other failure is a `*keysource.Error` or a transport error, which a verifier
reports as `KindKeyLookupFailed`. It caches nothing: every verification asks
identity, so a key deactivated or deleted is refused on the next request.

## Differences from AWS

- **No policies.** Permissions are the fixed rules above: admin principals may
  call every IAM operation in their account, IAM users none, and every active
  key works against every Tule service. Nothing here tells you whether a
  deployment's IAM policies are right. `AccessDenied` messages carry AWS's
  form without its policy explanation.
- **Users, their access keys and their tags only.** Groups, roles as IAM
  resources, policies, login profiles, MFA, SSH keys, certificates and every
  other IAM operation, and every STS operation but the three above, answer as
  an action AWS does not know: `400` `InvalidAction`. So does an IAM operation signed for `sts`,
  or the other way round, and a request whose `Version` is not the service's.
- **One role.** `AssumeRole` assumes `OrganizationAccountAccessRole` in a
  member account and nothing else. accounts records the `RoleName` given to
  `CreateAccount`, but the Organizations API does not expose it, so the role
  always has the AWS default name. The role's maximum session duration is one
  hour. Only the root user may assume it, and role chaining is not possible.
  A session stays valid until it expires even if its account is closed.
- **Some parameters are refused or not acted on.** `CreateUser` refuses
  `PermissionsBoundary` with `InvalidInput`, and `AssumeRole` refuses
  `Policy` and `PolicyArns` with `InvalidParameterValue`, since dropping them
  would report a user or session that is not what was asked for. `AssumeRole`'s `ExternalId`, `SerialNumber`, `TokenCode`,
  `SourceIdentity`, `Tags`, `TransitiveTagKeys` and `ProvidedContexts` are
  accepted and ignored: they have no effect here, the role trusting the root
  user without conditions. Responses carry no `PackedPolicySize` or
  `SourceIdentity`.
- **The root user's key cannot be managed.** It is configured, so creating,
  deactivating or deleting it through IAM fails with `InvalidInput`, where
  AWS lets the root user manage its own access keys. The root user's
  `CreateDate`, and its key's, is when the database was created.
- **Tags are on users only,** with no tag-based access control, since there
  are no policies.
- **Secrets are stored as they are.** SigV4 needs the secret itself to derive
  a signing key, so the database holds every secret in the clear; session
  tokens are kept as their SHA-256. Treat the database file as a credential.
- **Last use is recorded per request, not only on success.** A request whose
  signature verifies records its key's use, even when the operation then
  fails. Through the signing-key endpoint the use is recorded when the key is
  handed out, before the calling service checks the signature, so a request
  it then refuses is recorded too. Role sessions' keys are not tracked, and
  `GetAccessKeyLastUsed` with one fails with `NoSuchEntity`, as it does with
  a key of another account.
- **Choices where AWS documents none.** `ListUsers` returns users in order of
  their names without regard to case, `ListAccessKeys` keys in the order they
  were created, and `ListUserTags` and `GetUser` tags in order of their keys
  without regard to case. A `Marker` is opaque and only accepted back by the same
  listing with the same parameters; any other fails with `InvalidInput`.
  `ListUserTags` pages by position, so a tag set or removed between two pages
  can shift the second by one.
  `GetAccessKeyInfo` with a key this service never issued fails with
  `InvalidParameterValue`, where AWS decodes an account from any key ID.
  `UpdateAccessKey` to `Expired` fails with `InvalidInput`. A body that does
  not parse as a form is `MalformedQueryString`, with the `404` of the common
  errors reference.
- **Only `POST /`.** AWS also takes Query requests as `GET` with the
  parameters in the URL; here `GET /` is `405`.
- **Timestamps have second precision,** as AWS's responses show them.
- **Signature verification is request-level.** The method, path, query,
  signed headers and the body's hash are checked, along with the credential's
  key and token and a 15-minute clock skew. A request body larger than 1 MiB is
  refused. `UNSIGNED-PAYLOAD` is rejected, since it would leave the body, and
  so the `Action`, outside the signature.
- **No throttling and no eventual consistency.** A user or key is visible and
  usable as soon as the call that creates it returns.
- **Expired role sessions are kept.** Nothing deletes a session's record when
  it expires; it stays refused.
- **One process per database.** The store is one SQLite file reached through
  one connection, which serializes the server's own transactions; nothing
  coordinates two servers pointed at the same file.
- **Logs record the connection's peer address.** `X-Forwarded-For` is not
  trusted, since nothing is expected in front of this service and the header
  is unsigned.

## Development

```sh
make test       # unit tests
make test-e2e   # end-to-end tests: the app in-process, driven by the AWS SDKs
make lint
make image      # build ghcr.io/tulehq/identity:dev
make smoke      # build the image, run it, and check it serves signed requests
make push VERSION=0.1.0   # build for amd64 and arm64 and push
```

The cross-service end-to-end test builds the accounts service from source
and runs it. It looks for the checkout at `../accounts`, beside this one, or
at `TULE_E2E_ACCOUNTS_DIR` when set; CI checks out `tulehq/accounts` and sets
it.

## License

[MIT](LICENSE)
