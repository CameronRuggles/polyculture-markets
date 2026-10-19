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
git clone https://github.com/CameronRuggles/polyculture-markets ~/marketplace-src
cd ~/marketplace-src/marketplace
```

(The tree is `marketplace/` inside the project repo: it contains
`Cargo.toml`, `crates/`, `migrations/`, and `deploy/`.)

## 4. Choose the database password

Pick a password for the app's PostgreSQL role. It goes in exactly
two places, both on the VM: the role itself and the env file. Write
it, alone on one line, to a root-only file — the deploy script reads
it from there and passes it to psql as a variable (audit DL1: the
password used to travel through SQL strings and a `sed` pattern; any
characters are safe now, including `' " $ / & \`):

```sh
printf '%s' 'choose-a-long-random-password' | sudo tee /root/marketplace-db-password >/dev/null
sudo chmod 600 /root/marketplace-db-password
```

Keep the same password in your password manager. Never commit this
value, and never paste it into the repo's env template in your
working copy — the template ships with a `CHANGE-ME` placeholder on
purpose. (The script still accepts `MARKETPLACE_DB_PASSWORD` in the
environment as a fallback, with a warning; the file is the way.)

## 5. Deploy

```sh
cd ~/marketplace-src/marketplace
sudo MARKETPLACE_DB_PASSWORD_FILE=/root/marketplace-db-password \
     MARKETPLACE_BUILD_USER=<your normal login account> \
     sh deploy/deploy-demo.sh
```

The build runs as **your** account, never as root (audit DM3:
cargo executes every dependency's build script). If you would
rather build elsewhere entirely, pass
`MARKETPLACE_BIN_DIR=<dir with marketplace-app + media-worker>`
instead of `MARKETPLACE_BUILD_USER`; with neither, the script
refuses rather than build as root.

The script (idempotent — re-running it is the upgrade path):

1. Refuses if the env file selects mainnet or the production profile.
2. Builds release binaries (`marketplace-app`, `media-worker`),
   `--locked`, as the build user in a throwaway copy of the tree —
   or takes the prebuilt pair from `MARKETPLACE_BIN_DIR`.
3. Creates the `marketplace` system user and `/var/lib/marketplace`
   (including `media/` and `blobs/`).
4. Installs binaries to `/usr/local/bin` and the systemd unit.
5. Installs `/etc/marketplace/marketplace.env` from
   `deploy/env.demo.template` **only if absent** (your filled-in
   env file is never overwritten) and fills the DB password,
   percent-encoded into the connection URL — no plaintext password
   in the file.
6. Creates the PostgreSQL roles: `marketplace_migrator` (owns the
   database) and `marketplace` (the app). Creates the
   `marketplace_demo` database owned by the migrator.
7. Applies migrations in glob order, each at most once, **as the
   migrator role — never as the postgres superuser**. (On a host
   first deployed by an older script, superuser-owned tables are
   handed to the migrator automatically.)
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

Four things make up the instance (see `docs/operations.md` §3).
The key file is backed up **separately** from the rest (losing it
is not survivable; losing any other single part is):

```sh
# Database
sudo -u postgres pg_dump marketplace_demo | gzip > ~/marketplace-demo-db-$(date +%F).sql.gz
# Key file (mode 0600; store it somewhere at least as safe)
sudo cp /var/lib/marketplace/marketplace.key ~/marketplace.key.bak-$(date +%F)
# Message ciphertext files (BLOB_DIR) — without these, restored
# conversations list their messages but every download 404s
sudo tar czf ~/marketplace-demo-blobs-$(date +%F).tar.gz -C /var/lib/marketplace/blobs .
# Listing images (MEDIA_DIR) — without these, restored listings
# serve with every image missing
sudo tar czf ~/marketplace-demo-media-$(date +%F).tar.gz -C /var/lib/marketplace/media .
```

Copy all four off the VM. Restore drill (do it once, before you
need it) — restore into scratch locations, boot against the
restored set, and verify content actually serves:

```sh
sudo -u postgres createdb -O marketplace marketplace_restore_test
gunzip -c marketplace-demo-db-<date>.sql.gz | sudo -u postgres psql marketplace_restore_test
sudo -u postgres psql marketplace_restore_test -c '\dt'   # tables present?
mkdir -p /tmp/restore-test/blobs /tmp/restore-test/media
sudo tar xzf ~/marketplace-demo-blobs-<date>.tar.gz -C /tmp/restore-test/blobs
sudo tar xzf ~/marketplace-demo-media-<date>.tar.gz -C /tmp/restore-test/media
# Boot a scratch instance against the restored database + key file
# copy + restored blob/media dirs (see docs/operations.md §3), then:
#   - log in, open a conversation, download a message (must work)
#   - open a listing with an image (the image must load)
sudo -u postgres dropdb marketplace_restore_test
rm -rf /tmp/restore-test
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
