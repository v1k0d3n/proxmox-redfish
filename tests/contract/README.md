# Contract tests

These prove that a change to this daemon did not alter what it returns
over the wire. They talk to a *running* server, so they capture the
behaviour that is actually deployed rather than the behaviour the code
appears to have.

## Why

The daemon is the boot path for real clusters. A refactor that is
"obviously equivalent" is not good enough, because the failure mode is a
machine that will not provision, discovered hours later. Capture the old
behaviour, capture the new behaviour, diff them.

## Snapshots contain real infrastructure detail

A snapshot embeds MAC addresses, hostnames, storage pool names and
Proxmox task ids from the host it was taken against. `snapshots/` is
gitignored and must stay that way. Do not paste snapshots into issues.

Credentials are read from `REDFISH_USER` / `REDFISH_PASS` in the
environment and are never written into a snapshot.

## Capturing a baseline

Run this against the daemon you trust, before changing anything:

```bash
export REDFISH_USER='someuser@pve'
export REDFISH_PASS='...'
python capture.py \
  --base-url https://127.0.0.1:8000 --vm-id 1001 \
  --storage-id 1 --nic-id net0 \
  --out snapshots/baseline.json
```

`--storage-id` and `--nic-id` must be real ids for that VM. Read them
out of the `Storage` and `EthernetInterfaces` collections first; wrong
ids silently reduce coverage to a set of 404s that still "match".

Every endpoint is requested three times by default. Any value that moves
between passes is recorded as `<volatile>` and ignored by the diff, so
uptime and CPU load do not cause false failures.

## Gating a change

Start the modified daemon on a spare port, capture it, and diff:

```bash
python capture.py --base-url https://127.0.0.1:8001 --vm-id 1001 \
  --storage-id 1 --nic-id net0 --out snapshots/candidate.json
python compare.py snapshots/baseline.json snapshots/candidate.json
```

`compare.py` exits non-zero on any difference. Running the candidate on
a second port means the daemon under test never displaces the one that
is serving.

## Mutating tests

`--include-mutating` additionally exercises power actions and virtual
media. It changes VM state and uploads to your ISO storage, so point it
only at a disposable VM:

```bash
python capture.py --base-url https://127.0.0.1:8001 --vm-id 1001 \
  --include-mutating --iso-url http://127.0.0.1:8899/test.iso \
  --out snapshots/candidate-full.json
```

Record the VM's `ide2` and `boot` values before you start, and restore
them afterwards. Remove any ISOs the run uploaded.
