# Operations manual

How to run an instance of this marketplace: profiles, keys, backups,
retention, and upgrades. Written for the operator of a small
instance. The demo-specific walkthrough lives in
`deploy/DEPLOY-DEMO-RUNBOOK.md`; this manual covers every profile.

## 1. Deployment profiles

Configuration resolves once at startup from the environment and
**fails closed**: an unknown profile, an unknown network, or an
unconfirmed mainnet selection stops the process with the reason
printed. There are no silent fallbacks. (`crates/app/src/config.rs`
is the single resolver; the payments layer takes its network from
it and never reads the environment itself.)

| Variable | Values | Default |
|---|---|---|
| `DEPLOY_PROFILE` | `development` / `demo` / `production` | `development` |
| `INSTANCE_NETWORK` | `stagenet` / `testnet` / `mainnet` | `stagenet` |
| `MAINNET_CONFIRM` | the exact sentence `I ACCEPT MAINNET REAL FUNDS` | — |
| `MARKETPLACE_ID` | stable instance ID | `vespiary-market` |
| `SITE_NAME` | header name | `Polyculture Markets` |
| `BIND_ADDR` | listen address | `127.0.0.1:8080` |
| `REGISTRATIONS_OPEN` | `1`/`true` or `0`/`false` | open |
| `SOURCE_URL` | published source location (AGPL) | unset |
| `DATABASE_URL` | PostgreSQL connection string | local dev default |
| `KEY_FILE_PATH` | key file location | `./marketplace.key` |

Network rules, enforced in code:

- **Mainnet requires the production profile AND the exact
  `MAINNET_CONFIRM` sentence** (case-sensitive, untrimmed). In the
  development and demo profiles mainnet is refused even with the
  sentence — a dev box or the demo must never hold real-funds
  addresses.
- **Testnet is refused in production.**
- Stagenet is always available: it is the safe direction.

Profiles (§19):

- **Development** — plain HTTP on loopback, non-Secure `session`
  cookie so a local browser works, seed/fixture workflows available.
- **Demo** — the hosted stagenet demo: `__Host-` Secure cookies,
  same code as production, stagenet only. The app still binds
  loopback; reach it through an SSH tunnel or a TLS reverse proxy.
- **Production** — documented shape in this release: `__Host-`
  Secure cookies behind a TLS-terminating proxy or a Tor hidden
  service (see §19 of the spec: for onion-only, keep
  `HiddenServicePoWDefensesEnabled 1` and friends in `torrc`, no
  HSTS). A production **mainnet** instance additionally requires
  the pre-mainnet sign-off (PRE-MAINNET-CONFIRMATION-SHEET section
  1), which is the owner's separate decision — this software ships
  configured for stagenet and stays there until that sign-off
  exists.

The instance's profile, network, and retention values are shown on
its own `/limitations` page. Check there after any config change;
what that page says is what the running process resolved.

## 2. The key file — custody and backup

The key file (`KEY_FILE_PATH`) is a 32-byte master secret stored
**outside the database**, mode 0600. From it the server derives,
by HMAC with domain labels:

- the buyer-token key (reputation facts name buyers by token, so
  facts cannot be re-linked to accounts without it);
- the content-encryption key (TOTP secrets and disclosed dispute
  evidence are encrypted at rest with it).

**Losing the key file** makes stored disclosures and TOTP secrets
undecryptable and orphans buyer-token history (the reputation
facts themselves remain, permanently un-linkable). **Leaking it**
with a database copy defeats the encryption-at-rest layer. Rules:

1. Back it up **separately from the database** — different medium,
   different place. Never in the same archive, never in the repo.
2. Mode 0600, owned by the service account, nothing else reads it.
3. Losing it is not recoverable by design. Test your backup (§3).

## 3. Database backup and restore

Back up with `pg_dump` (compressed). Rolling 30 days (§20).

```sh
pg_dump "$DATABASE_URL" | gzip > backup-$(date +%F).sql.gz
```

**Restore procedure — tested at the Stage 10 gate** (against a
scratch database; the production database is never the test):

```sh
createdb marketplace_restore_test
gunzip -c backup-<date>.sql.gz | psql marketplace_restore_test
psql marketplace_restore_test -c '\dt'        # tables present
# point a scratch run at it and log in:
DATABASE_URL=postgres://…/marketplace_restore_test KEY_FILE_PATH=/path/to/keyfile-copy ./marketplace-app
dropdb marketplace_restore_test
```

A restore is only complete with the key file (§2): database +
matching key file = an instance; either alone is a partial copy.

## 4. Retention (spec §20)

An in-process scheduler runs the retention pass hourly
(`RETENTION_INTERVAL_SECS`). Automated in this release:

| Data | Rule |
|---|---|
| Read notifications | deleted 30 days after being read |
| Sessions | deleted 7 days after expiry |
| Security events | deleted after 30 days |
| Dispute disclosures | deleted 180 days after the dispute resolves |

Periods are env-overridable (`NOTIFICATIONS_READ_RETENTION_DAYS`,
`SESSIONS_EXPIRED_RETENTION_DAYS`, `SECURITY_EVENTS_RETENTION_DAYS`;
the disclosure period follows the Stage 9 config — the value the
dispute page states to users). The Limitations page displays the
instance's actual values.

All retention and expiry cutoffs are computed **by the database**
(`now()` in the DELETE/UPDATE statements), so the application and
the data can never disagree about what is old; there is exactly one
clock for data decisions. Keeping that host clock honest (NTP/NTS,
including on an onion-only host with no other outbound traffic) is
an operator duty — a badly skewed clock ages sessions and orders
wrong in both directions.

**Not automated** (see `docs/unverified.md`): order/invoice/terms
purge at terminal + 180 days with tombstones, message-payload
windows, and report windows. Until those ship, old orders remain —
if your threat model needs them gone, that is a manual operator
task, and the Limitations page says so honestly rather than
claiming a purge that does not happen.

## 5. Logging

- Production runs with **no debug logging**. The app prints only
  startup state (bind, profile, network), sweep/retention counts,
  and error markers — never request data.
- Security-relevant events go to the `security_events` table with
  an allow-listed field set (actor, event type, target, time); no
  query strings, no form bodies, no addresses beyond the target
  reference.
- Systemd captures stdout: `journalctl -u marketplace-demo`.

## 6. Upgrades

1. Back up (§3) — database and key file, separately.
2. Re-run `deploy/deploy-demo.sh` (demo) or replace the binary and
   restart the unit (manual installs). Migrations apply in glob
   order, each at most once; there are no down-migrations — a bad
   release is rolled back by restoring the backup, never by
   un-applying schema.
3. Confirm `/limitations` still shows the expected profile and
   network before announcing the upgrade.
4. Record the deployed binary's SHA-256 (the deploy script prints
   it). Signed releases are not yet produced by this project — do
   not claim otherwise anywhere public (see `docs/unverified.md`).

## 7. The release checklist (operator's, per release)

- [ ] Full test suite + crypto-backend guard green
      (`deploy/check-crypto-backend.sh`).
- [ ] `docs/unverified.md` reviewed; every open item is disclosed
      on the instance Limitations page or accepted in writing.
- [ ] Backup restored into a scratch database and the app booted
      against it (§3).
- [ ] Key file backup verified present and separate (§2).
- [ ] `/limitations` values match the intended configuration.
- [ ] For mainnet: PRE-MAINNET-CONFIRMATION-SHEET section 1 signed.
      Absent that signature, the instance stays on stagenet.
