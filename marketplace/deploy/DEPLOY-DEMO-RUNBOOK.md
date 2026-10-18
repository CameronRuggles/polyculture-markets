# Deploy runbook — hosted stagenet DEMO on a single Google Cloud VM

**Purpose.** Stand up the marketplace demo (spec v2, Direct Payments
v1, Stage 10 demo profile) on one small Google Cloud VM so the owner
can click through the real interface and review it. **Stagenet only.**
Nothing in this runbook touches mainnet, real funds, or a production
configuration — the demo profile, the binary, and the deploy script
each independently refuse mainnet.

**Time.** About 30–45 minutes of wall-clock, most of it waiting for
the first release build. Re-deploys after that are one command.

---

## 1. Create the VM

- Google Cloud Console → Compute Engine → Create instance.
- Size: **e2-small (2 GB) or e2-medium (4 GB)**. Do NOT use the
  always-free e2-micro: its 1 GB RAM is too small for the Rust app +
  PostgreSQL together.
- Image: **Debian 12 (bookworm)**. Disk: 20 GB is plenty.
- Firewall: allow SSH (tcp/22) only. The app binds loopback on the
  VM; there is deliberately **no public web port** (step 6 covers
  how you reach it).
- Note the external IP; you'll SSH to it.

## 2. Base packages

```sh
ssh <user>@<vm-ip>
sudo apt-get update
sudo apt-get install -y postgresql postgresql-client git curl \
  build-essential pkg-config clang nettle-dev ca-certificates
sudo systemctl enable --now postgresql
```

Install the pinned Rust toolchain (the repo pins 1.99.0 in
`rust-toolchain.toml`):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
export PATH="$HOME/.cargo/bin:$PATH"
```

## 3. Get the source

Clone or copy the marketplace tree to the VM, e.g.:

```sh
git clone <repo-url> ~/marketplace-src
cd ~/marketplace-src/marketplace
```

(The tree is `marketplace/` inside the project repo: it contains
`Cargo.toml`, `crates/`, `migrations/`, and `deploy/`.)

## 4. Choose the database password

Pick a password for the app's PostgreSQL role. It goes in exactly
two places, both on the VM: the role itself and the env file. The
deploy script takes it from your shell environment and writes both:

```sh
export MARKETPLACE_DB_PASSWORD='choose-a-long-random-password'
```

Never commit this value, and never paste it into the repo's env
template in your working copy — the template ships with a
`CHANGE-ME` placeholder on purpose.

## 5. Deploy

```sh
cd ~/marketplace-src/marketplace
sudo MARKETPLACE_DB_PASSWORD="$MARKETPLACE_DB_PASSWORD" sh deploy/deploy-demo.sh
```

The script (idempotent — re-running it is the upgrade path):

1. Refuses if the env file selects mainnet or the production profile.
2. Builds release binaries (`marketplace-app`, `media-worker`).
3. Creates the `marketplace` system user and `/var/lib/marketplace`.
4. Installs binaries to `/usr/local/bin` and the systemd unit.
5. Installs `/etc/marketplace/marketplace.env` from
   `deploy/env.demo.template` **only if absent** (your filled-in
   env file is never overwritten) and fills the DB password.
6. Creates the PostgreSQL role + `marketplace_demo` database.
7. Applies migrations in glob order, each at most once.
8. Restarts the service and health-checks
   `http://127.0.0.1:8080/` on the VM until it answers, then prints
   the deployed binary's SHA-256.

If the health check fails: `journalctl -u marketplace-demo -n 100`.
The most common cause is a config error printed at startup — the
binary fails closed and names the offending variable.

## 6. Reach the demo

The app listens on the VM's loopback only. From your own machine:

```sh
ssh -L 8080:127.0.0.1:8080 <user>@<vm-ip>
```

Then open **http://127.0.0.1:8080/** in your browser. You'll see the
demo banner: this instance is on the Monero **stagenet**; every coin
is a valueless test coin.

Optional, if the demo needs a shareable URL: put a TLS reverse
proxy (e.g. Caddy) in front with a real domain, proxying to
127.0.0.1:8080. Do not simply open port 8080 in the firewall and
serve plain HTTP to the internet — passphrases would cross the
network unencrypted.

## 7. First-run checklist

- [ ] Home page loads and shows the stagenet demonstration banner.
- [ ] Register a throwaway account; save the recovery code it shows.
- [ ] Footer on every page shows: Policy · Limitations · Payment
      risks · Source · Version — and the network reads **stagenet**.
- [ ] `/limitations` shows profile **demo**, network **stagenet**,
      and the retention values.
- [ ] Register a second account; have a moderator approve it as a
      seller; walk an order end-to-end with stagenet coins via the
      seller helper (see `seller-helper/SELLER-GUIDE.md`).

## 8. Backups

Two things, backed up **separately** (losing either one alone is
survivable; losing the key file is not — see `docs/operations.md`):

```sh
# Database
sudo -u postgres pg_dump marketplace_demo | gzip > ~/marketplace-demo-db-$(date +%F).sql.gz
# Key file (mode 0600; store it somewhere at least as safe)
sudo cp /var/lib/marketplace/marketplace.key ~/marketplace.key.bak-$(date +%F)
```

Copy both off the VM. Restore drill (do it once, before you need it):

```sh
sudo -u postgres createdb -O marketplace marketplace_restore_test
gunzip -c marketplace-demo-db-<date>.sql.gz | sudo -u postgres psql marketplace_restore_test
sudo -u postgres psql marketplace_restore_test -c '\dt'   # tables present?
sudo -u postgres dropdb marketplace_restore_test
```

## 9. Cost control

Stop the VM when nobody is reviewing: Compute Engine → the instance
→ **Stop**. A stopped e2-small costs only its disk. Start it again
and the service comes back with the instance (`systemctl enable`
was set by the deploy script); data persists on the disk.

## 10. Teardown

```sh
sudo systemctl disable --now marketplace-demo
sudo rm /etc/systemd/system/marketplace-demo.service /usr/local/bin/marketplace-app /usr/local/bin/media-worker
sudo -u postgres dropdb marketplace_demo
sudo -u postgres dropuser marketplace
sudo rm -rf /var/lib/marketplace /etc/marketplace
```

Then delete the VM itself in the console if the demo is over.

---

**Hard rules for this demo.** Stagenet only; no real Monero; no
mainnet env values anywhere on the box (the binary refuses them in
this profile anyway); throwaway accounts only; the demo database is
disposable and should be treated as public-inspectable.
