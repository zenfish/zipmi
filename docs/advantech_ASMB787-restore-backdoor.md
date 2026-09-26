# ASMB-787 — `raw 0x32 0x66` restore-defaults: full execution chain

> **Superseded/corrected:** the former “backdoor” and unauthenticated-reachability conclusion came from swapped dispatch fields. The command is Administrator (`0x04`) with a zero-byte dispatcher constraint. Use the corrected [HTML note](advantech_ASMB787-restore-factory-defaults.html) and [canonical CSV](../zipmi/data/sources/advantech-asmb787-oem-dispatch.csv).

Evidence around the factory-reset command in the Advantech ASMB-787 BMC
(AMI MegaRAC SP-X 4.0 / AST2600), from static analysis and vBMC observations.

```
ipmitool raw 0x32 0x66            NetFn 0x32 (g_AMI), Cmd 0x66
        │
        ▼
[1] dispatch gate      FUN_0002b0f0 (libipmimsghndlr.so)
        │  GetMsgHndlrMap(0x32) → g_AMI table ; GetCmdHndlr(0x66) → entry
        │  entry.Priv (+1) == 0x04  → Administrator required
        │  priv OK → call entry.Handler (+4) as a direct C call
        ▼
[2] handler            AMIRestoreDefaults @ 0x3c150 (libipmimsghndlr.so)
        │  SetPendStatus(0x3f, 0xf)
        │  PostPendTask(0x3f, 0, 0, priv&0xf, channel)
        │  *cc = 0x00   ← returns SUCCESS immediately (async)
        ▼
[3] pending-task path (task id 0x3f; exact script call site not recovered)
        │  firmware also contains the restore script and exec imports
        ▼
[4] /etc/restoredefaults.sh restore
             rm -rf /conf/*
             cp -Rp /etc/defconfig/* /conf
```

## [1] The privilege gate — confirmed, not inferred

`GetCmdHndlr` matches the **Cmd byte only**. The privilege decision is in the
dispatch loop `FUN_0002b0f0`:

```c
// local_30 = matched CmdHndlr_T entry
if (/* corrected dispatch privilege at local_30 + 1 is insufficient */) {
    *cc = 0xC7; return;                                     // priv mismatch
}
...
*cc-on-priv-fail = 0xD4;                                    // insufficient privilege
...
iVar5 = (**(code **)(local_30 + 4))(...);                   // call entry.Handler (+4)
```

The corrected registration entry carries privilege `0x04` (Administrator) at
offset +1 and request length `0x00` at offset +8. The old analysis reversed
those meanings and does not establish an authentication bypass on KCS or LAN.

The handler is invoked as a **direct C function pointer** (`entry+4`) inside the
IPMI daemon. Nothing is exec'd *at dispatch time*.

## [2] The handler is a thin async shim

`AMIRestoreDefaults` (decompiled) does almost nothing itself — it queues work
and returns success:

```c
undefined4 AMIRestoreDefaults(param_1, param_2, undefined1 *param_3, param_4) {
    SetPendStatus(0x3f, 0xf);
    pvVar1 = pthread_getspecific(...);              // current channel/priv
    PostPendTask(0x3f, 0, 0, (uint)pvVar1 & 0xf, param_4);
    *param_3 = 0;                                   // completion code = success
    return 1;
}
```

So the IPMI response is **0x00 (success) before the reset has happened** —
the wipe runs asynchronously as pending task **0x3f**.

## [3]–[4] The async task runs a root shell script

`libipmimsghndlr.so` imports **`popen`** and **`execv`** and carries the string
`restoredefaults.sh` (@ `0x9b184`) plus `/conf` in its `.rodata`. These facts
support a likely link to pending task 0x3f, but the exact call site is obscured
by PIC/GOT indirection and was not recovered. The script behavior below is
independently established; the command-to-script edge remains inferred.

### The script — two copies on the BMC filesystem

- `/etc/restoredefaults.sh`
- `/usr/local/lib/restoredefaults.sh` (identical)

```sh
restore_function()
{
    echo -n "Restoring to default configuration...  "
    rm -rf /conf/*
    cp -Rp /etc/defconfig/* /conf
    if [ $? != 0 ]; then echo "Failed."; exit 1; else echo "Done."; fi
}

case "$1" in
    restore)
        if [ -x /usr/local/bin/flasher ]; then
            if [ -f /var/flasher.initcomplete ]; then restore_function; fi
        else
            restore_function
        fi
        ;;
esac
```

The reset is a literal **`rm -rf /conf/*`** followed by repopulation from the
read-only factory skeleton **`/etc/defconfig`**. `/conf` is the persistent
config overlay — mounted from `/etc/defconfig` at first boot by
`mountall.sh` / `defaulthost.sh`.

### What `/conf` holds (so: what gets wiped)

From `preservecfg`'s `/etc/defconfig/*` list, `/conf` is the entire BMC
identity and security state:

- **Credentials:** `passwd`, `shadow`, `BMC%d` user DB, `radiuspriv.ini`
- **Remote auth:** `ldap.conf`, `activedir.conf`, `radius.conf`, `pam_*`,
  `nsswitch.conf`
- **Keys / TLS:** `sshd_config` + host keys (see `RestoreUsrSSHDir` in
  `libuserm.so`), `stunnel.conf`
- **Network:** `interfaces`, `ncml.conf`, `dns.conf`, `hosts`, `bond.conf`,
  `vlansetting.conf`, `hostname`
- **Services / policy:** `snmpcfg.conf`, `ntp.conf`, `dcmi.conf`, `hpm.conf`,
  `rsyslog.conf`, `hosts.allow` / `hosts.deny`, SDR data

The script is a **full factory wipe of users, passwords, network, and service
config** when its guard permits execution. The vBMC command path did not reach
that wipe, so end-to-end command-to-wipe execution is not dynamically proved.

### Preserve-configuration caveat

MegaRAC has a "preserve configuration" feature (`PreserveFlag`,
`DualImgPreserveConf`, the `libipmiamioemprsvconf` OEM table, and the
`preservecfg` binary) that can exempt selected `/conf` domains from the wipe.
The bare `restoredefaults.sh restore` shown above is unconditional; whether the
task-0x3f path consults the preserve mask first is the one open detail. Either
way the command remains destructive when its operational preconditions hold.
Its corrected dispatch entry requires Administrator privilege.

## Bottom line

| Question | Answer |
|----------|--------|
| Reachable unauthenticated? | Not established. The corrected entry requires Administrator (`0x04`); LAN requires an Administrator session. |
| Does it run a script on the BMC OS? | **Yes** — `/etc/restoredefaults.sh restore`, as root. |
| What does the script do? | `rm -rf /conf/*` then `cp -Rp /etc/defconfig/* /conf`. |
| Blocking? | No — handler returns CC 0x00 immediately; reset runs as async task 0x3f. |
| Advantech-specific? | This result is bound to the ASMB-787 firmware. Other AMI products require their own dispatch evidence. |

## Dynamic confirmation (live vBMC, 2026-08-14)

Fired against the emulated ASMB-787 (`vbmc advantech-asmb787`, qemu ast2600).
LAN answers on loopback inside the guest (the NC-SI wall only blocks *external*
traffic); default creds `admin/admin`, cipher 17.

```
# ipmitool -I lanplus -C 17 -H 127.0.0.1 -U admin -P admin raw 0x32 0x66
# → (empty response, RC=0)   == completion code 0x00, returned immediately
```

Observed, in order:

1. **CC 0x00 returned instantly** — confirms the async shim: the handler
   answers success before any reset happens.
2. **A full re-provision storm followed** — redis, stunnel, and the VM
   app restarted; config services re-read `/conf`; the serial session was reset
   to a `login:` prompt. This is consistent with the pending-task pathway, but
   no process trace directly tied the storm to `restoredefaults.sh`.
3. **The `rm -rf /conf/*` did NOT run over the IPMI path.** `/conf` stayed at
   102 entries, the sentinel survived. Cause, confirmed on the box:

   ```
   /usr/local/bin/flasher        → present
   /var/flasher.initcomplete     → ABSENT
   ```

   The script's guard `if [ -f /var/flasher.initcomplete ]; then restore_function`
   gates the wipe. This vBMC is perpetually mid-bring-up (the same reason
   ext-net is WIP — `flasher` never reaches init-complete), so the destructive
   branch is structurally skipped. Arming the marker then re-firing still lost
   the race: the restore storm restarts `flasher`, which clears its own marker
   before task 0x3f's script re-checks it.

4. **Running the mechanism synchronously (guard satisfied, no storm race) —
   glass from orbit:**

   ```
   # touch /var/flasher.initcomplete; sh /etc/restoredefaults.sh restore
   pre_conf=102  sentinel=/conf/ZZZ_NUKE_SENTINEL
   Restoring to default configuration...  Done.
   post_conf=72  sentinel=GONE
   ```

   `/conf` 102 → **72** (the `/etc/defconfig` skeleton count), the sentinel and
   all 101 operational files destroyed. Exactly `rm -rf /conf/*; cp -Rp
   /etc/defconfig/* /conf`, plus a `libpreserveconf.c` message.

5. **Resurrection** — `vbmc restart` (boot copies pristine `mtdflash.bin` →
   `mtdflash-run.bin`): `/conf` back to 101, root login OK, IPMI `Get Device ID`
   answers again.

**Takeaways.** The command is accepted and returns success asynchronously on
the vBMC. The destructive script behavior is independently verified, but the
vBMC command path skipped the wipe because the marker was absent. Production
marker state and end-to-end command-to-wipe behavior remain untested.

## Provenance

- Binary: `usr/local/lib/libipmimsghndlr.so.13.22.0` (ARM32, stripped-ish, AMI MegaRAC SP-X 4.0)
- Ghidra project `asmb787`; functions `FUN_0002b0f0` (gate), `AMIRestoreDefaults` @ `0x3c150`
- Scripts: `/etc/restoredefaults.sh`, `/usr/local/lib/restoredefaults.sh` in the unpacked rootfs
- Canonical command/privilege catalog: [advantech_ASMB787-command-reference.html](advantech_ASMB787-command-reference.html)
