# ovnctl

A Python port of the OVN/OVS deployment, diagnostic and teardown shell
suite. Same topology, same commands, same output — one executable, and
every command split into named steps you can run individually.

```
chmod +x ovnctl                   # once, if the bit was lost in transit

sudo ./ovnctl deploy              # the whole build, in order
sudo ./ovnctl -n deploy           # preview it, change nothing
sudo ./ovnctl setup --list-steps  # what one command actually does
sudo ./ovnctl setup --only host-interface
sudo ./ovnctl diagnose
sudo ./ovnctl reconcile           # after a reboot: reapply runtime state
```

---

## Layout

```
ovnctl                      entry point (runs from a checkout, no install)
configs/
  ovn-settings.yaml         the single source of truth
  ovn-internal-ranges.conf  legacy fallback range list
state/
  ovn-deploy-state          deployment tracker (runtime data, not config)
ovnsuite/
  cli.py                    argparse root, dispatch, exit codes
  config.py                 settings parser + in-place editors
  context.py                logging, dry-run, command execution
  state.py                  the deployment tracker
  netcalc.py                CIDR maths
  steps.py                  the step framework
  ovn.py                    read-only ovs-vsctl / ovn-nbctl / ovn-sbctl wrappers
  inventory.py              the VM inventory and its selectors
  libvirtutil.py            virsh domain/interface lookups
  paths.py                  split-vs-flat layout resolution
  commands/                 one module per original script
```

---

## Surviving a reboot

The OVN databases are persistent; the runtime half of a deployment is
not. After a reboot three things are gone and nothing puts them back:

* `external-ids:system-id` — `ovs-ctl start --system-id=random` rewrites
  it at every boot from `/etc/openvswitch/system-id.conf`, so the chassis
  is renamed and every `Port_Binding.chassis` and gateway pin quietly
  stops matching. Set a fixed `[setup].system_id`; `setup` and
  `reconcile` write it to both places.
* host-if's link state, address and routes — kernel state on an OVS
  internal port, lost every time.
* ovn-controller's claim on any tap recreated after it started.

`ovnctl reconcile` reapplies all of it and is safe to re-run:

```
sudo ./ovnctl reconcile                    # reassert, report anything unsafe
sudo ./ovnctl reconcile --repair-identity  # also delete stale chassis rows
sudo ./ovnctl reconcile --install-unit     # run it at every boot
sudo ./ovnctl reconcile --install-nm-profile   # persist host-if via NetworkManager
```

`--install-unit` writes `/etc/systemd/system/ovn-reconcile.service`,
ordered after `ovn-controller.service`, and enables it.

`--install-nm-profile` covers the host-if half declaratively instead:
it generates
`/etc/NetworkManager/system-connections/host-if.nmconnection` from
`[setup]` in `ovn-settings.yaml` — `host_if_ip`/`host_if_prefix` as the
address, `host_if_mac` as the cloned MAC, and every `host_routes` entry
as a static route via `lrp_host_cidr`. The config stays the single
source of truth, so the profile cannot drift from what `setup` and
`reconcile` apply. Preview it with `-n` before writing.

The profile sets `never-default=true` and writes no `gateway=` key. An
`ipv4.gateway` on host-if would install a default route through
`lr-core` that competes with the host's real uplink on metric; the host
reaches the VM segments through the explicit `host_routes` only.

NetworkManager will not accept this profile if its OVS plugin has
already claimed host-if as an `ovs-interface` device —
`--install-nm-profile` detects that, says so, and tells you to use
`--install-unit` on that host.

Note that `Port_Binding.chassis` survives a reboot too, so a binding can
name a chassis nothing is running under. `diagnose` resolves the chassis
*name* rather than just checking one is set, which is the difference
between a live binding and a fossil.

Both layouts the shell suite supported still work: `configs/` + `state/`
beside the executable, or everything flat in one directory. Overrides:
`OVN_CONFIG_FILE`, `OVN_CONF_DIR`, `OVN_STATE_DIR`, `OVN_STATE_FILE`,
`OVN_ROOT` — or `--config PATH` / `--state-file PATH`.

Python 3.9+, standard library only. No PyYAML, no third-party packages.

Nothing needs installing — `./ovnctl` runs straight from the directory
and puts the package on `sys.path` itself, so it works under `sudo` and
from an absolute path in cron or a systemd unit. If the executable bit
did not survive the trip, either `chmod +x ovnctl` or run it as
`sudo python3 ovnctl ...`. To install it on `PATH` instead:
`pip install .` provides the same `ovnctl` command.

---

## Command mapping

| shell | python |
|---|---|
| `ovn-setup.sh` | `ovnctl setup` |
| `ovn-localnet-internal.sh` | `ovnctl localnet-internal` |
| `ovn-localnet-external.sh` | `ovnctl localnet-external` |
| `ovn-vm-config.sh` | `ovnctl vm-config` |
| `ovn-vm-isolation.sh` | `ovnctl vm-isolation` |
| `ovn-acl.sh` | `ovnctl acl` |
| `ovn-vm-attach.sh` | `ovnctl vm-attach` |
| `ovn-pcap.sh` | `ovnctl pcap` |
| `ovn-diagnose.sh` | `ovnctl diagnose` |
| `ovndelete.sh` | `ovnctl delete` (alias `teardown`) |
| `ovn-deploy.sh` | `ovnctl deploy` |
| `ovn-runbook.sh` | `ovnctl runbook` |
| `tools/ovn-show` | `ovnctl show` |

Every flag the originals accepted is still accepted: `--remove`,
`--trace SRC DST`, `--status`, `--verify`, `--list`, `--add-target`,
`--del-target`, `--list-targets`, `--clear-targets`, `--start`, `--stop`,
`--restart`, `--purge-db`, `--keep-br-int`, `--teardown`, `--all`,
`--no-header`, `-o FILE`.

---

## Steps

This is the part the shell suite could not do. Each command declares its
steps by name:

```
$ ./ovnctl localnet-internal --list-steps
Available steps for localnet-internal (in run order):
   1. check-router    verify lr-core exists
   2. bridge-nic      create br-internal and enslave the NIC
   3. bridge-mapping  extend ovn-bridge-mappings
   4. transit-switch  transit switch + localnet port
   5. attach-router   router port + gateway chassis pin
   6. routes          the 0.0.0.0/0 route to the first-hop firewall
   7. confirm-no-nat  warn if NAT is configured on lr-core
```

| flag | effect |
|---|---|
| `--list-steps` | list and exit |
| `--only A,B` | run just those |
| `--skip A,B` | run everything else |
| `--from A` | start at A, continue to the end |

Steps always execute in declaration order no matter what order you name
them in — selection changes *which* steps run, never the sequence, because
the sequence is the part that has to hold.

`ovnctl deploy` uses the same framework, with the whole subcommands as its
steps, so `ovnctl deploy --from vm-config` resumes a half-finished build.

`--list-steps` deliberately needs neither root nor a working OVN install:
it is documentation, and documentation you can only read on a healthy
deployment is not much use when the deployment is broken.

---

## Global flags

| flag | effect |
|---|---|
| `-v`, `--verbose` | full narration (default is one summary line) |
| `-n`, `--dry-run` | print the commands, change nothing |
| `--config PATH` | alternative settings file |
| `--state-file PATH` | alternative tracker |
| `--no-color` | never emit ANSI escapes |

These normally come before the subcommand, but `ovnctl setup -n` works
too — the parser hoists them.

**The output contract is unchanged from the shell suite:** success is a
single `OK:` line; `-v` narrates; `--dry-run` prints commands and nothing
else; warnings and errors always go to stderr.

Dry-run listings reflect the *current* state of the system, because every
command queries before deciding what to change. On a fully deployed host
you see only the remaining delta. For the full build sequence, generate it
from a clean host or after a teardown.

---

## Fixes carried in the port

The shell suite had drifted out of sync with its own configuration and did
not run on a clean checkout. These are behavioural differences, all
deliberate:

**`localnet-external` and `diagnose` aborted immediately.** Both called
`require_cfg` for a `[localnet_external]` block (`br_asa`, `phys_nic`,
`ln_asa`, `lrp_asa`, `lrp_asa_mac`, `ls_ext_asa`, `physnet_label`,
`policy_priority`, `gateway_chassis_priority`) and an `[asa_addressing]`
section that no longer exist — the yaml documents that section as
policy-only since the second NIC was removed. Policy-only is now the
primary path; the legacy physical-uplink steps run only when those keys
are actually present, so both topologies work.

**`diagnose` had three latent faults**: an undefined `_iso_vms` variable
silently broke the live non-member isolation proof; three `cfg <section>
<key> <default>` calls passed a third argument to a two-argument function
that exits on a miss; and the missing-config abort above meant a
single-NIC host could not be diagnosed at all.

**`next_hop` validation was documented but never implemented.** The yaml
states it must sit inside `transit_subnet`; nothing checked. It is now an
error when set explicitly and off-link, and a warning when inherited from
`lan_gateway`.

**`--dry-run` wrote to the deployment tracker.** `state_mark` was called
unconditionally, so previewing `ovn-setup.sh` left a `setup` flag behind
and every later diagnose run believed the deployment existed. Tracker
writes are now no-ops in a dry run.

**A partial run no longer claims a full deployment.** Recording `setup`
after `--only switches` would make diagnose expect a router, gateway ports
and a host interface that were never created, reporting each as a failure
instead of as "not deployed yet".

**`ovn-internal-ranges.conf` is parsed, not sourced.** The shell `source`d
it, so a stray command in a config file would execute.

**`unit_exists` no longer uses `systemctl … | grep -q`.** grep exits on
first match, systemctl takes SIGPIPE, and the pipeline reports failure
despite having matched.

Two behaviours worth keeping in mind, both preserved and both verified by
`diagnose`:

- Port-group ACL matches are always scoped with `inport`/`outport ==
  @<group>`. An unscoped match applies switch-wide — this caused a real
  outage once.
- `ovn-trace` verdicts match `ct_mark.blocked = 1` as well as `drop;`.
  Once any ACL is `allow-related` the pipeline is stateful and northd
  compiles a drop into a `ct_commit` with no `output`, so matching only
  `drop;` reports stateful drops as ALLOW.

---

## Configuration

`configs/ovn-settings.yaml` is parsed by a faithful port of the original
awk parser, not by a YAML library. This is intentional: the real file
contains constructs a strict YAML reader interprets differently — bare
values with trailing `#`, `key: []` acting as a list header that later
`- item` lines append to, duplicated keys inside commented examples.
Matching the original parser exactly means existing configuration files
keep working unchanged.

There are no built-in defaults. A missing settings file or a missing
required key stops the run with a message naming the key, rather than
silently deploying something that does not match the configuration.

---

## Typical use

```bash
# preview a build on a clean host, then run it
sudo ./ovnctl -n deploy | less
sudo ./ovnctl deploy
sudo ./ovnctl diagnose

# fix one thing without re-running everything
sudo ./ovnctl setup --only host-interface
sudo ./ovnctl acl --verify

# prove a policy does what you think
sudo ./ovnctl localnet-external --trace 172.31.1.36 8.8.8.8
sudo ./ovnctl vm-isolation --trace 172.31.1.36 172.31.1.18

# hand someone a command list they can run without this tooling
./ovnctl runbook -o runbook.sh
./ovnctl runbook --all -o full.sh

# read-only views
sudo ./ovnctl show switches
sudo ./ovnctl show acls

# tear it down
sudo ./ovnctl delete --purge-db
```

Exit codes: `0` success, `1` failure (including `diagnose` finding
problems), `2` usage error, `130` interrupted.