# Custom Authentication Service

A learning project that builds a complete authentication flow **by hand** with Spring Boot and
Spring Security: mobile number + one-time password (OTP) login, JWT access tokens, rotating refresh
tokens, and role/permission based authorization.

> **Status:** a solid, well-tested learning implementation, **not production-ready**. See
> [Known limitations](#known-limitations) before putting anything real behind it.

## How it works

```
 1. POST /auth/otp/request   mobile number ─────────────► OTP generated, hashed, stored, sent (console in dev)
 2. POST /auth/otp/verify    mobile number + OTP ───────► user found/created ─► access token + refresh token
 3. GET  /me, other APIs     Authorization: Bearer <access token> ─► Spring Security filter validates the JWT
 4. POST /auth/token/refresh refresh token ─────────────► new access token + NEW refresh token (old one is used up)
 5. POST /auth/logout        refresh token ─────────────► session revoked
```

Two different flows are deliberately separated:

* **Login** (steps 1 and 2) proves who you are with an OTP and issues tokens.
* **Every other request** (step 3) is authenticated only by the access token, in the Spring Security
  filter chain, with no database lookup.

## Tech stack

| | |
|---|---|
| Language / build | Java 25, Gradle (wrapper included) |
| Framework | Spring Boot 4.1.1 (Web MVC, Data JPA, Validation, Security) |
| Modularity | Spring Modulith (feature modules, enforced boundaries) |
| Database | MariaDB (Hibernate) |
| JWT | JJWT 0.13.0 (HS256) |
| API contract | Smithy 1.74.0, generating OpenAPI |
| Tests | JUnit 5, Mockito, AssertJ, MockMvc |

## Prerequisites

* JDK 25
* MariaDB running locally
* Nothing else: Gradle comes from the wrapper (`./gradlew`)

## Getting started

### 1. Create the local database

```sql
CREATE DATABASE auth_service_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'admin'@'localhost' IDENTIFIED BY 'admin';
GRANT ALL PRIVILEGES ON auth_service_db.* TO 'admin'@'localhost';
```

These credentials are for **local development only**. They live in `application-dev.properties`.

### 2. Run the application

```bash
SPRING_PROFILES_ACTIVE=dev ./gradlew bootRun
```

In IntelliJ, set **Active profiles** to `dev` in the run configuration.

The `dev` profile creates the tables (`ddl-auto=update`), prints OTPs to the console instead of
sending an SMS, and logs masked request bodies. At startup (in every profile) a seeder creates the
`USER` and `ADMIN` roles if they are missing. Without a profile the application refuses to start: the
base configuration has no secret defaults on purpose.

### 3. Try it

```bash
# 1. Request an OTP; read the code from the application log ("OTP for 9198... = 123456")
curl -s -X POST localhost:8080/auth/otp/request \
  -H 'Content-Type: application/json' -d '{"mobileNumber":"9876543210"}'

# 2. Verify it; the response contains the tokens
curl -s -X POST localhost:8080/auth/otp/verify \
  -H 'Content-Type: application/json' -d '{"mobileNumber":"9876543210","otp":"<code>"}'

# 3. Call a protected endpoint
curl -s localhost:8080/me -H "Authorization: Bearer <accessToken>"

# 4. Rotate the tokens
curl -s -X POST localhost:8080/auth/token/refresh \
  -H 'Content-Type: application/json' -d '{"refreshToken":"<refreshToken>"}'

# 5. Log out
curl -i -X POST localhost:8080/auth/logout \
  -H 'Content-Type: application/json' -d '{"refreshToken":"<refreshToken>"}'
```

## API

The API is described in a [Smithy model](api-model/model/auth.smithy). The generated OpenAPI document
is in [`docs/api/AuthService.openapi.json`](docs/api/AuthService.openapi.json).

| Method and path | Auth | Success | Notes |
|---|---|---|---|
| `POST /auth/otp/request` | public | `202` | Always `202` for a well-formed number |
| `POST /auth/otp/verify` | public | `200` tokens | `401` wrong, expired or unknown OTP (indistinguishable), `429` too many attempts, `403` disabled account |
| `POST /auth/token/refresh` | public | `200` tokens | `401` invalid, expired, revoked or reused token |
| `POST /auth/logout` | public | `204` | Always `204` |
| `GET /me` | Bearer | `200` | The caller as seen from the token |
| `/demo/*` | Bearer + permission | | Sample endpoints for `@PreAuthorize`; delete when real ones exist |

Errors share one shape: `{"error":"CODE","details":{...}}`. Token responses carry
`Cache-Control: no-store`. Every response has an `X-Request-Id` header, which also appears in every log
line of that request.

### Regenerating the API document

```bash
./gradlew :api-model:publishOpenApi
```

`ApiContractTest` fails the build if the controllers and the Smithy model disagree about which
operations exist, so the model cannot silently drift from the code.

## Design

### Modules

```
org.example.sprintbootcustomauthentication
├── auth        controllers, AuthenticationService (orchestrates OTP, user and tokens), error handling
├── otp         OTP generation, hashing, expiry and attempt limits
├── user        users, roles and permissions
├── token       access tokens (JWT) and refresh tokens
├── security    Spring Security filter chain and the JWT authentication filter
├── shared      MobileNumber value object, UserAuthorities, Clock, request logging
└── demo        sample permission-protected endpoints
```

Modules depend on each other only through their public API (the package root); `internal`
subpackages are hidden. `shared` depends on nothing.

### Security decisions

* **OTP:** 6 digits from `SecureRandom`; stored as an HMAC-SHA256 hash keyed with a server secret (a
  plain hash of 6 digits would be trivially reversible); compared in constant time; single use; 5
  minute expiry; 5 attempts; one row per mobile number.
* **Concurrency:** OTP verification locks the row (`SELECT ... FOR UPDATE`) at `READ_COMMITTED`;
  OTP issue and user creation are single atomic upserts; refresh tokens are read with a row lock.
* **Access token:** JWT, HS256, 15 minutes, with `iss`, `aud`, `sub`, `iat`, `exp`, `jti`, `roles` and
  `permissions`. Tokens without `exp`, unsigned tokens, and tokens for another issuer or audience are
  rejected.
* **Refresh token:** opaque 256-bit random value; only its SHA-256 hash is stored; valid 30 days; used
  once. Each login starts a **family**; each refresh stays in the family. Presenting an already-used
  token revokes the entire family (theft detection). Disabling a user revokes all their sessions.
* **Authorization:** roles contain permissions; both travel in the access token; `@PreAuthorize`
  checks them; a new refresh re-reads them from the database.
* **Spring Security:** stateless, CSRF disabled (bearer tokens, no cookies), default deny, JSON 401
  and 403 responses, and no default generated user.
* **Hygiene:** uniform error responses (no OTP or account enumeration), no stack traces or SQL in
  responses, request bodies masked in logs, secrets only from the environment outside `dev`.

### Configuration

| Property | Environment variable | Purpose |
|---|---|---|
| `spring.datasource.url` / `.username` / `.password` | `DB_URL`, `DB_USERNAME`, `DB_PASSWORD` | Database |
| `app.otp.secret` | `OTP_SECRET` | HMAC key for OTP hashes |
| `app.jwt.secret` | `JWT_SECRET` | HS256 signing key, at least 32 bytes |
| `app.otp.length` / `ttl` / `max-attempts` | | 6 / 5m / 5 |
| `app.jwt.issuer` / `audience` / `access-ttl` / `refresh-ttl` | | `auth-service` / `auth-service-api` / 15m / 30d |
| `app.http-logging.log-bodies` | | Log masked request bodies (on in `dev` only) |

Outside the `dev` profile all secrets and the datasource must be supplied, and an `OtpSender` bean
must exist (the console sender is `dev` only). The schema is validated, not created
(`ddl-auto=validate`), so it must be provisioned separately.

## Testing

```bash
./gradlew test
```

Most tests are unit tests with mocks and need no database. The application context test starts the
real application with the `dev` profile, so it needs the local MariaDB from the setup above. The
`test` task builds the Smithy model first.

## Known limitations

This is **not production-ready**. Main gaps:

* **No rate limiting or send cooldown.** `/auth/otp/request` can be used to flood a phone or run up SMS
  costs, and re-requesting OTPs resets the attempt counter, which enables brute force.
* **No real SMS sender** (console only), and no TLS, CORS or security-header review for deployment.
* **Schema is created by Hibernate in `dev`;** there are no migrations (Flyway or Liquibase).
* **Native MariaDB SQL and locking are only verified by hand,** not by integration tests against a real
  database (Testcontainers would fix this).
* **No audit log,** no cleanup job for expired OTP and refresh-token rows, and no endpoint to manage
  roles (promote users with SQL).
* **Access tokens cannot be revoked:** after logout or theft detection, an access token stays valid
  until it expires (15 minutes).
* **Strict reuse detection:** a client that retries a refresh after losing the response loses its
  session; there is no grace window.
* **SMS is a weak authentication factor** (SIM-swap and SS7 attacks); high-value actions need a stronger one.

The per-phase checklist is in [`docs/best-practices.md`](docs/best-practices.md).

## Project layout

```
.
├── api-model/               Smithy API model and OpenAPI generation (separate Gradle subproject)
├── docs/
│   ├── api/                 generated OpenAPI document
│   └── best-practices.md    security and design checklist per phase
├── src/main/java/...        application code (modules above)
├── src/main/resources/      application.properties, application-dev.properties
└── src/test/java/...        unit, web-layer and contract tests
```
