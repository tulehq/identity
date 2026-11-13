# identity

An AWS IAM- and STS-compatible identity service that keeps users, roles,
managed and inline policies, access keys and role sessions in a local SQLite
database. It is built to stand in for IAM and STS in local development and
end-to-end tests: point an AWS SDK at it and the usual user, role, policy,
access key, caller identity and AssumeRole calls work, and identity policies
decide who may do what.

It also issues the keys the other Tule services verify. A service asks
identity's [signing-key endpoint](#the-signing-key-endpoint) for the SigV4
signing key of a request's credential and checks the signature itself, so a
key created here works against every Tule service. A service assumes a role
as an AWS service, such as a function's execution role, through the
[assume-role endpoint](#the-assume-role-endpoint).

It is not a production identity service: secrets are stored as they are, and
only identity-based policies and role trust policies are evaluated
([below](#principals-and-permissions)).

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
| `DeleteUser` | Fails with `DeleteConflict` while the IAM user has access keys, attached policies or inline policies |
| `CreateAccessKey` | The only response that carries the secret. At most two keys per user, then `LimitExceeded` |
| `ListAccessKeys` | Paginated. Without `UserName`, the root key lists itself |
| `UpdateAccessKey` | `Active` or `Inactive` |
| `DeleteAccessKey` | |
| `GetAccessKeyLastUsed` | For a user's key or the root user's |
| `TagUser` / `UntagUser` | At most 50 tags on a user |
| `ListUserTags` | Paginated, in order of their keys |
| `CreatePolicy` | A customer managed policy; its document is `v1`, the default. Names are unique in the account without regard to case. Takes `Path`, `Description` and `Tags` |
| `GetPolicy` | With its tags. `AttachmentCount` counts the calling account's users and roles |
| `ListPolicies` | `Scope` (`All`, `AWS`, `Local`), `OnlyAttached`, `PathPrefix`, paginated. `PolicyUsageFilter=PermissionsBoundary` lists none |
| `DeletePolicy` | Fails with `DeleteConflict` while attached, or while it has versions besides its default |
| `CreatePolicyVersion` | At most 5 versions, then `LimitExceeded`. `SetAsDefault` makes it the default. Version IDs are never reused |
| `GetPolicyVersion` | With its document, URL-encoded as IAM returns documents |
| `ListPolicyVersions` | Newest first, paginated |
| `DeletePolicyVersion` | Not the default version: `DeleteConflict` |
| `SetDefaultPolicyVersion` | |
| `AttachUserPolicy` / `DetachUserPolicy` | A customer managed policy of the account or an AWS managed one. At most 10 per user, then `LimitExceeded` |
| `ListAttachedUserPolicies` | In the order they were attached, filtered by `PathPrefix`, paginated |
| `PutUserPolicy` / `GetUserPolicy` / `DeleteUserPolicy` | Inline policies; together at most 2,048 characters per user, white space excluded, then `LimitExceeded` |
| `ListUserPolicies` | Names in order, paginated |
| `CreateRole` | `AssumeRolePolicyDocument` (a trust policy, at most 2,048 characters without white space), `Path`, `Description`, `MaxSessionDuration` (3600 to 43200, default 3600) and `Tags`. Names are unique in the account without regard to case |
| `GetRole` | With its tags and trust policy, URL-encoded; a trusted user or role since deleted shows as its unique ID |
| `ListRoles` | Filtered by `PathPrefix`, paginated |
| `UpdateRole` | `Description` and `MaxSessionDuration`, each when given |
| `UpdateAssumeRolePolicy` | |
| `DeleteRole` | Fails with `DeleteConflict` while the role has attached or inline policies. Its sessions are orphaned: see below |
| `AttachRolePolicy` / `DetachRolePolicy` / `ListAttachedRolePolicies` | As for users; at most 20 per role |
| `PutRolePolicy` / `GetRolePolicy` / `ListRolePolicies` / `DeleteRolePolicy` | As for users; together at most 10,240 characters per role |

One AWS managed policy is shipped: `arn:aws:iam::aws:policy/AdministratorAccess`,
with the document, description, dates and version (`v1`) the AWS Managed
Policy Reference gives it. Every account can see and attach it; nobody can
change or delete it (`InvalidInput`).

A policy document is checked against the IAM JSON policy grammar by
[tule.dev/policy](https://github.com/tulehq/policy), and a document that
breaks it fails with `MalformedPolicyDocument` and the library's message. An
identity policy may not name a `Principal`; a trust policy must. Documents
are stored and returned as they were sent. A managed policy is at most 6,144
characters without white space.

STS (`2011-06-15`):

| Operation | Notes |
|---|---|
| `GetCallerIdentity` | Any active principal, whatever its policies |
| `GetAccessKeyInfo` | The account of any key this service issued, the root user's included, whatever its status. Needs `sts:GetAccessKeyInfo`, as v0.1.0 did not |
| `AssumeRole` | Any role whose trust policy allows the caller, [below](#assumerole) |

IDs have AWS's formats: `AIDA` and 17 base32 characters for a user (21 in
all), `AROA` and 17 for a role, `ANPA` and 17 for a managed policy, `AKIA`
and 16 for an access key, `ASIA` and 16 for a role session's key, and a
secret is 40 characters of the base64 alphabet. A user's ARN is
`arn:aws:iam::<account>:user<path><name>`, a role's
`arn:aws:iam::<account>:role<path><name>` and a managed policy's
`arn:aws:iam::<account>:policy<path><name>`; a role session's is
`arn:aws:sts::<account>:assumed-role/<role name>/<session>` and its `UserId`
is `<role ID>:<session>`; the root user's is `arn:aws:iam::<account>:root`
and its `UserId` is the account ID.

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

Requests are authorized by policy, as AWS authorizes them within an account:

- **The root user** is always allowed, and is never evaluated against
  policies.
- **Every other principal** is evaluated on every IAM and STS request against
  its identity policies: a user's inline policies and the default versions of
  its attached managed policies, or a session's role's, as they are at the
  time of the request. An explicit `Deny` wins; otherwise the request needs
  an `Allow`. A request no policy allows is `AccessDenied` (`403`), "User:
  \<arn\> is not authorized to perform: \<action\> on resource: \<arn\>
  because no identity-based policy allows the \<action\> action", or "...
  with an explicit deny in an identity-based policy".
- **`GetCallerIdentity`** is always allowed, as AWS documents: it needs no
  permission and an explicit deny does not stop it.

Each operation is evaluated as the action and resource the Service
Authorization Reference lists for it: `iam:<Operation>` or
`sts:<Operation>`, on the user, role or policy it names, with its path, such
as `iam:CreateUser` on `arn:aws:iam::<account>:user/<path><name>`. An action
the reference lists no resource type for (`ListUsers`, `ListRoles`,
`ListPolicies`, `GetAccessKeyInfo`) is evaluated on `*`. The condition keys
supplied are `aws:PrincipalArn`, `aws:PrincipalAccount`, `aws:PrincipalType`,
`aws:userid`, `aws:username` (users), `aws:SourceIp`, `aws:CurrentTime`,
`aws:EpochTime`, `aws:SecureTransport`, `aws:RequestedRegion` and
`aws:PrincipalTag/<key>`, plus `iam:PolicyARN` for the attach and detach
operations, `sts:RoleSessionName` for `AssumeRole`, and the tag keys below;
they fill policy variables such as `${aws:username}` too.

Each principal acts in its own account: users the root user creates are the
management account's, users a member account's session creates are that
account's.

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

A role can be assumed when its trust policy allows the caller, evaluated
with tule.dev/policy (`AWS` principals: the account ID, its root ARN, a user
ARN, a role ARN, which a session of that role matches, or `*`), and:

- the caller's own identity policies allow `sts:AssumeRole` on the role's
  ARN, unless the caller is the root user. Within the caller's account a
  trust policy that names the caller directly, by its user, role or session
  ARN or by `*`, is enough on its own, as AWS documents for resource-based
  policies in one account ("How AWS enforcement code logic evaluates requests
  to allow or deny access"); one that names only the account is not. An
  explicit `Deny` in the caller's policies always refuses.
- the role is in the caller's account, or the caller is in the
  organization's management account and the role is in an `ACTIVE` member
  account.

Role names are matched with their case. Anything else, a role that does not
exist included, is `AccessDenied`, as AWS refuses a role that does not exist.

For a member account, identity asks the accounts service, with Organizations
calls signed with the root user's key, which account manages the
organization (`DescribeOrganization`) and whether the account is an active
member (`DescribeAccount`). The management account accounts reports must be
`TULE_Identity_AccountID`, the root user's; when it is not, the root user's
`AssumeRole` into a member account fails with `500` `InternalFailure` naming
both, and the mismatch is logged. Without an accounts endpoint only roles of
the caller's own account can be assumed.

`OrganizationAccountAccessRole` is created in a member account once, by the
first `AssumeRole` of it from the management account that passes every
check, as Organizations would have created it with the account: path `/`, a
maximum session duration of an hour, a trust policy for
`arn:aws:iam::<management>:root`, and `AdministratorAccess` attached. A
refused request creates nothing. It is an ordinary role after that, and can
be changed or deleted; a deleted one is never created again.

`DurationSeconds` is 900 to 43200 by the model and defaults to 3600; more
than the role's `MaxSessionDuration` fails with `ValidationError`. The
session expires then: its token is refused with `ExpiredToken` from that
moment. A session carries its role's policies, as they are at each request.

## The signing-key endpoint

An internal endpoint, not an AWS API, that the other Tule services verify
requests through. It is `POST /_internal/signing-key`, which no Query request
uses, since those are all `POST /`.

- **Authentication.** A call is SigV4-signed with the root user's key, for the
  signing name `identity` in `us-east-1`. Anything else is refused, `403`
  with the sigv4 Kind as the code, before the body is read.
- **Request.** The credential scope of the request the caller wants to verify,
  and the endpoint version it speaks, as JSON:

  ```json
  {"AccessKeyId": "AKIA...", "SessionToken": "...", "Date": "20261113",
   "Region": "us-east-1", "Service": "secretsmanager", "Version": 2}
  ```

  `SessionToken` is left out when the request carries none. `Version` is 2
  for the v0.2.0 client; a request without it, as the v0.1.0 client sends
  it, is answered as v0.1.0 answered.
- **Response.** `200` with the derived signing key for that date, region and
  service, base64-encoded, and the principal the key belongs to. It never
  returns a secret. At version 2 the principal also carries `Root`, true for
  the root user's key, which is never evaluated against policies, and
  `Policies`, the identity policy documents in effect for anyone else (inline,
  then the default versions of the attached managed policies; a session's
  are its role's), and the response carries `Version`:

  ```json
  {"Principal": {"AccountId": "000000000000",
                 "Arn": "arn:aws:iam::000000000000:user/dev",
                 "AccessKeyId": "AKIA...",
                 "Policies": [{"Version": "2012-10-17", "Statement": [...]}]},
   "SigningKey": "...",
   "Version": 2}
  ```

  Without `Version` in the request, the response has none of `Root`,
  `Policies` and `Version`, so a v0.1.0 client keeps working and simply gets
  no policies.

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
reports as `KindKeyLookupFailed`. It asks for version 2 and fills
`sigv4.Principal.Root` and `sigv4.Principal.Policies` from the answer; an
identity that answers below version 2, v0.1.0, is a `*keysource.Error` with
the code `VersionUnsupported`, since it cannot say what the principal may do.
It caches nothing: every verification asks
identity, so a key deactivated or deleted is refused on the next request.

## The assume-role endpoint

An internal endpoint, not an AWS API, through which a Tule service assumes a
role as an AWS service principal, as Lambda assumes a function's execution
role. `AssumeRole` matches a trust policy against the caller's ARN, and no
caller is a service, so a role that trusts
`{"Service": "lambda.amazonaws.com"}` (the Lambda Developer Guide's execution
role) is assumed through this endpoint instead. It is
`POST /_internal/assume-role`.

- **Authentication.** As the signing-key endpoint's: SigV4 with the root
  user's key, for the signing name `identity` in `us-east-1`. Anything else
  is refused, `403` with the sigv4 Kind as the code, before the body is read.
- **Request.**

  ```json
  {"RoleArn": "arn:aws:iam::000000000000:role/fn-exec",
   "RoleSessionName": "invocation", "ServicePrincipal": "lambda.amazonaws.com",
   "SourceArn": "arn:aws:lambda:us-east-1:000000000000:function:fn",
   "SourceAccount": "000000000000", "DurationSeconds": 900}
  ```

  `ServicePrincipal` is a service principal, DNS labels ending in
  `.amazonaws.com`. `RoleSessionName` follows `AssumeRole`'s rules.
  `DurationSeconds` is 900 to 43200 and at most the role's
  `MaxSessionDuration`, or left out for an hour. `SourceArn`, an ARN, and
  `SourceAccount`, 12 digits, are optional: the resource the service acts
  for and its account, such as a function's.
- **Evaluation.** The role's trust policy must allow the service principal
  `sts:AssumeRole`, evaluated as `AssumeRole` evaluates it, with its user and
  role principals bound to their unique IDs, and with `aws:SourceArn` and
  `aws:SourceAccount` from the request, as AWS services supply them, so a
  trust policy can guard against the confused deputy problem. Identity
  policies are not
  evaluated, as a service principal has none. Role names are matched with
  their case. Nothing about the role changes, and
  `OrganizationAccountAccessRole` is never created here.
- **Response.** `200` with an ordinary session of the role, which carries the
  role's policies, as an `AssumeRole` session does:

  ```json
  {"Credentials": {"Expiration": "2026-11-13T10:15:00Z", "AccessKeyId": "ASIA...",
                   "SecretAccessKey": "...", "SessionToken": "..."},
   "AssumedRoleUser": {"AssumedRoleId": "AROA...:invocation",
                       "Arn": "arn:aws:sts::000000000000:assumed-role/fn-exec/invocation"}}
  ```

- **Refusals.** `404` `NoSuchRole`, `403` `NotTrusted` (the trust policy does
  not allow the service), `400` `InvalidDuration`, and `400` `InvalidRequest`
  for a body that is not a request or a malformed field. A failure of the
  store is `500`.

### The service role client

`tule.dev/identity/servicerole` is the endpoint's client:

```go
c, err := servicerole.New(servicerole.Config{
	Endpoint:        "http://localhost:9030",
	AccessKeyID:     rootKeyID,
	SecretAccessKey: rootSecret,
})
s, err := c.AssumeServiceRole(ctx, roleARN, "invocation", "lambda.amazonaws.com",
	15*time.Minute, servicerole.WithSourceArn(functionARN),
	servicerole.WithSourceAccount(accountID))
```

It returns `servicerole.ErrNoSuchRole`, `ErrNotTrusted` and
`ErrInvalidDuration` for those refusals, and a `*servicerole.Error` or a
transport error otherwise.

## Differences from AWS

- **Identity policies and trust policies only.** Permissions boundaries,
  session policies, service control policies and groups are not part of
  evaluation; resource-based policies of other services are not evaluated
  here. Policy evaluation is tule.dev/policy's; see its README for what it
  covers.
- **Users, roles, managed and inline policies and access keys only.** Groups,
  instance profiles, login profiles, MFA, SSH keys, certificates, policy and
  role tagging operations, `ListEntitiesForPolicy`, and every other IAM
  operation, and every STS operation but the three above, answer as an action
  AWS does not know: `400` `InvalidAction`. So does an IAM operation signed
  for `sts`, or the other way round, and a request whose `Version` is not the
  service's.
- **One AWS managed policy.** Only `AdministratorAccess` is shipped. Its
  `PolicyId` is the one AWS reports, which the managed policy reference does
  not list; its dates are the reference's, to the minute.
- **The root user may call `AssumeRole`.** AWS refuses root credentials;
  here the root user is how a member account is first reached, as in v0.1.0.
  Role chaining works as the trust policies allow, for an hour at most, as
  AWS limits it: a chained `DurationSeconds` over 3600 is `ValidationError`.
  A session stays valid until it expires even if its account is closed.
- **A session of a deleted role is orphaned.** A session is bound to its
  role's ID, as AWS binds roles to unique IDs, so a role created again with
  the same name is another role. Until it expires the orphaned session still
  authenticates and may call `GetCallerIdentity`; every other action is
  `AccessDenied`, no trust policy allows it, and the signing-key endpoint
  reports it with no policies. AWS documents no answer for such a session.
- **Trust policies name unique IDs.** As AWS does, a user or role ARN in a
  trust policy's `Principal` is bound to that principal's unique ID when the
  policy is saved (`CreateRole`, `UpdateAssumeRolePolicy`), and an ARN no
  user or role has is `MalformedPolicyDocument`, "Invalid principal in
  policy". A user or role deleted and created again under the same ARN is
  another principal, which the trust policy does not name until it is saved
  again; `GetRole` and `ListRoles` then show the old unique ID in place of
  the ARN. Account IDs, root ARNs, role session ARNs, `*`, service principals
  and condition keys such as `aws:PrincipalArn` are not bound. The policy is otherwise returned
  as it was saved; where an ID replaces an ARN, its white space is not kept.
  A trust policy that names a principal by its unique ID, as `GetRole` shows
  a deleted one, is refused on `UpdateAssumeRolePolicy` as an invalid
  principal; whether AWS accepts a unique ID there is not verified.
- **Some parameters are refused or not acted on.** `CreateUser` and
  `CreateRole` refuse `PermissionsBoundary` with `InvalidInput`, and
  `AssumeRole` refuses `Policy`, `PolicyArns`, `Tags`, `TransitiveTagKeys`
  and `SourceIdentity` with `InvalidParameterValue`, since a session does not
  carry session policies, session tags or a source identity, and dropping
  them would report a session that is not what was asked for.
  `AssumeRole`'s `ExternalId` is supplied to the trust policy as
  `sts:ExternalId`; `SerialNumber`, `TokenCode` and `ProvidedContexts` are
  accepted and not supplied as condition keys. Responses carry no
  `PackedPolicySize` or `SourceIdentity`, and roles no `RoleLastUsed`.
- **The root user's key cannot be managed.** It is configured, so creating,
  deactivating or deleting it through IAM fails with `InvalidInput`, where
  AWS lets the root user manage its own access keys. The root user's
  `CreateDate`, and its key's, is when the database was created.
- **Tags are set on create for roles and policies,** and with `TagUser` on
  users. Tag conditions are evaluated with the keys the Service
  Authorization Reference lists: `aws:ResourceTag/<key>` from the tags of
  the user, role or managed policy acted on (and `iam:ResourceTag/<key>` for
  a user or role), `aws:RequestTag/<key>` and `aws:TagKeys` from the tags of
  `CreateUser`, `TagUser`, `CreatePolicy` and `CreateRole` (`aws:TagKeys`
  from `UntagUser`'s keys), and `aws:PrincipalTag/<key>` from the caller's
  tags, a user's own or a session's role's.
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
  can shift the second by one. `ListRoles` and `ListPolicies` are in order of
  names without regard to case, `ListPolicyVersions` newest first, the
  attached-policy listings in the order of attachment, and the inline-policy
  listings in order of names. Inline policy names are case sensitive. A
  change to an AWS managed policy is `InvalidInput`.
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

## Upgrading from v0.1.0

v0.2.0 is a breaking release:

- **Policies are enforced.** v0.1.0 let the root user and
  `OrganizationAccountAccessRole` sessions call every IAM operation and IAM
  users none. Now every principal but the root user needs a policy that
  allows each action. `OrganizationAccountAccessRole` keeps its access by
  having `AdministratorAccess` attached; an IAM user needs policies for what
  it did not do before either, and `AssumeRole` needs a trust policy that
  allows the caller.
- **Role sessions from v0.1.0 are dropped.** The database migration deletes
  them, since they name no stored role to take permissions from; they lasted
  an hour at most, and `AssumeRole` issues new ones.
- **`DeleteUser` refuses a user with policies**, attached or inline, with
  `DeleteConflict`.
- **The signing-key endpoint** answers v0.1.0 clients as before. The v0.2.0
  `keysource` client needs a v0.2.0 identity, and fills `sigv4.Principal.Root`
  and `Policies`, which `tule.dev/sigv4` v0.3.0 added.

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
