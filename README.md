# Access Control — demo application

[![CI](https://github.com/Spomky-Labs/access-control-demo/actions/workflows/ci.yml/badge.svg)](https://github.com/Spomky-Labs/access-control-demo/actions/workflows/ci.yml)

A working Symfony application built to exercise
[`spomky-labs/access-control-lib`](https://github.com/Spomky-Labs/access-control-lib) and
[`spomky-labs/access-control-bundle`](https://github.com/Spomky-Labs/access-control-bundle) —
authorization for PHP and Symfony: deciding whether a *requester* may perform an *action* on a
*subject*, under given *circumstances*.

Documentation for the library itself lives at **[acf.spomky-labs.com](https://acf.spomky-labs.com/)**.

This is not a snippet gallery. Every page is a real question put to the library through a real entry
point, and the whole thing is covered by a test suite that asserts on the decisions rather than on
the status codes.

## Running it

```bash
composer install
symfony server:start -d
```

Then open the URL the server prints. No database is needed: users and documents are in memory.

Sign in with `user` / `user`, `manager` / `manager` or `admin` / `admin` — the password is the
username. What each account *holds* is narrower than what it *reaches*: `security.role_hierarchy`
is declared once and the library reads it, so an admin satisfies a `ROLE_MANAGER` rule without
holding that role.

## How it is laid out

The demo follows the order the questions come up. The menu is generated from
[`src/Service/Catalogue.php`](src/Service/Catalogue.php), which is the one place the map lives.

| Section | The question | What is there |
| --- | --- | --- |
| **Guards** (`/guards`) | where is a decision applied? | an attribute on a controller and on a class, a policy about a subject, rules in configuration, a workflow guard |
| **Decisions** (`/decisions`) | how is the verdict reached? | five combining algorithms, the same request under two of them, policy shapes, `AtLeastOneOf`, an expression, a closure |
| **Requesters** (`/requesters`) | who is asking? | impersonation, delegation (RFC 8693), the access environment |
| **Reasons** (`/reasons`) | what can be seen afterwards? | verdicts with their reasons, deciding for other accounts, the audit trail, the profiler panel |

## What it demonstrates

**Entry points.** `#[AccessPolicy]` on controllers and on console commands, declarative URL rules
(path, method, IP, expression, HTTPS channel) that need no attribute at all, Workflow `guard:`
expressions, Twig, and the programmatic path through the manager.

**Extension points, all written in `src/`.** Application voters ([`DocumentVoter`](src/Security/DocumentVoter.php),
[`ComplianceVoter`](src/Security/ComplianceVoter.php), [`EditorialBoardVoter`](src/Security/EditorialBoardVoter.php),
[`EntryPointVoter`](src/Security/EntryPointVoter.php)), a combining algorithm of the application's own
([`TwoKeyStrategy`](src/Security/Strategy/TwoKeyStrategy.php) — a two-key rule none of the four shipped
ones expresses), a composite policy the library does not ship
([`#[DuringBusinessHours]`](src/Security/Attribute/DuringBusinessHours.php) and
[its handler](src/Security/Handler/DuringBusinessHoursHandler.php)), and an audit trail built from the
library's events ([`AccessAuditSubscriber`](src/Security/AccessAuditSubscriber.php)). Each one is a
service purely by implementing an interface — the tags are autoconfigured.

**Migration.** [`LegacyAuditVoter`](src/Security/LegacyAuditVoter.php) is a *Security* voter, untouched,
still voting through the bridge. Nothing in that file knows the bundle exists.

**Without Security at all.** The kernels under [`tests/Standalone/`](tests/Standalone/) register the
bundle and no `SecurityBundle`, and still decide: the role hierarchy on the library's own key,
declarative rules, `#[AccessPolicy]`, Security's `#[IsGranted]`, the `AbstractController` helpers,
and a guarded workflow — with no firewall, no token and no user provider.

## Console

Commands are guarded by the same attributes. There is no logged-in user on a console, so `--as`
stands in a service identity.

```bash
php bin/console app:report:generate --as=admin      # ROLE_ADMIN
php bin/console app:document:purge --force --as=admin  # #[When]: only guarded with --force
php bin/console app:audit:run --as=manager          # #[AtLeastOneOf]
php bin/console app:access:check VIEW 2 --as=user   # verdict, reason and every vote
php bin/console app:entry-point:check               # the access environment, console side
```

A refused command exits `113`, the code the console already means by "not allowed to run". Two of
them answer `77` instead, through [`DeniedExitCodeListener`](src/Console/DeniedExitCodeListener.php):
an exit status belongs to the scripts around a command, not to the rule that refused it.

Add `--profile -v` to any of them and follow the printed token to read the **Access Control**
profiler panel.

## Tests

```bash
vendor/bin/phpunit
```

The suite is part of the demo. Beyond the usual web tests it exercises the testing tools both
packages ship:

- `AccessOutcomeAssertionsTrait` — assertions on an answer already in hand, no container involved
- `AccessDecisionStrategyTestTrait` — a vote matrix for a custom combining algorithm
- `AccessPolicyHandlerTestTrait` with `FixedOutcomeAccessPolicy` — a composite handler exercised
  without a voter, a manager or a requester anywhere in sight
- `AccessControlAssertionsTrait` (bundle) — asserting *which* attribute was refused and by *which*
  voter, where a 403 says only that something was

Two tests exist to keep the demo itself honest: `CatalogueTest` fails if a page is added without a
place in the map, and `SmokeTest` renders every route so a template error in a leaf cannot hide
behind a green suite.

## Versions

Both packages are required at `1.0.*@dev` — the branch is published, there is no tagged release
yet. This application tracks that branch on purpose, which is what makes it useful: when the
library moves, the suite here says so.
