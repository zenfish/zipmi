# ASMB-787 — `raw 0x32 0x66` restore-defaults: full execution chain

What actually happens when the ASUS-style factory-reset command hits the
Advantech ASMB-787 BMC (AMI MegaRAC SP-X 4.0 / AST2600). Traced statically in
Ghidra + the unpacked rootfs.

```
ipmitool raw 0x32 0x66            NetFn 0x32 (g_AMI), Cmd 0x66
        │
        ▼
[1] dispatch gate      FUN_0002b0f0 (libipmimsghndlr.so)
        │  GetMsgHndlrMap(0x32) → g_AMI table ; GetCmdHndlr(0x66) → entry
        │  entry.Priv (+8) == 0x00  → not 0xff, compared to session priv
        │  priv OK → call entry.Handler (+4) as a direct C call
        ▼
[2] handler            AMIRestoreDefaults @ 0x3c150 (libipmimsghndlr.so)
        │  SetPendStatus(0x3f, 0xf)
        │  PostPendTask(0x3f, 0, 0, priv&0xf, channel)
        │  *cc = 0x00   ← returns SUCCESS immediately (async)
        ▼
[3] pending-task worker (task id 0x3f, libipmimsghndlr.so — imports popen + execv)
        │  runs the restore script on the BMC Linux OS
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
if ((*(byte *)(local_30 + 8) != 0xff) &&                    // entry.Priv, sentinel check
   ((uint)*(byte *)(local_30 + 8) != *(uint *)(param_1 + 0x68))) {
    *cc = 0xC7; return;                                     // priv mismatch
}
...
*cc-on-priv-fail = 0xD4;                                    // insufficient privilege
...
iVar5 = (**(code **)(local_30 + 4))(...);                   // call entry.Handler (+4)
```

Two facts fall out, and both were open questions until now:

- **`0xff` is a real sentinel.** The gate literally tests `entry.Priv != 0xff`
  *before* comparing. A `0xff` priv byte **skips the dispatcher check** and lets
  the handler self-enforce (this is why `AMIResetPassword`/`AMISetRootPassword`
  carry `0xff`). It is not "requires impossibly-high privilege."
- **`0x00` has no floor.** `AMIRestoreDefaults` carries `Priv = 0x00`, so it
  passes the gate at the lowest privilege. On the **KCS / system interface**
  (host-side, no session, no RMCP+ auth) a local OS-admin issues it with **zero
  BMC credentials** — the ASUS "run as administrator" note.

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
`restoredefaults.sh` (@ `0x9b184`) plus `/conf` in its `.rodata`. The task-0x3f
worker uses them to run the script below. (The exact call site is obscured by
PIC/GOT indirection in the stripped binary, but the script name + the exec
imports + the shim's `PostPendTask(0x3f)` live in this one library and nowhere
else.)

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

So `raw 0x32 0x66` is a **full factory wipe of users, passwords, network, and
service config** — reverting the BMC to shipped defaults (default creds, DHCP,
etc.), executed as **root via a shell script** on the BMC OS.

### Preserve-configuration caveat

MegaRAC has a "preserve configuration" feature (`PreserveFlag`,
`DualImgPreserveConf`, the `libipmiamioemprsvconf` OEM table, and the
`preservecfg` binary) that can exempt selected `/conf` domains from the wipe.
The bare `restoredefaults.sh restore` shown above is unconditional; whether the
task-0x3f path consults the preserve mask first is the one open detail. Either
way the command is reachable at `Priv = 0x00`.

## Bottom line

| Question | Answer |
|----------|--------|
| Reachable unauthenticated? | Yes on KCS/host-side (`Priv=0x00`, `iface=all`). LAN still needs a session; floor is 0. |
| Does it run a script on the BMC OS? | **Yes** — `/etc/restoredefaults.sh restore`, as root. |
| What does the script do? | `rm -rf /conf/*` then `cp -Rp /etc/defconfig/* /conf`. |
| Blocking? | No — handler returns CC 0x00 immediately; reset runs as async task 0x3f. |
| Advantech-specific? | No — `g_AMI`/`AMIRestoreDefaults` is stock AMI MegaRAC (see [oem-handler-lineage.md](oem-handler-lineage.md)); expected AMI-wide. |

## Provenance

- Binary: `usr/local/lib/libipmimsghndlr.so.13.22.0` (ARM32, stripped-ish, AMI MegaRAC SP-X 4.0)
- Ghidra project `asmb787`; functions `FUN_0002b0f0` (gate), `AMIRestoreDefaults` @ `0x3c150`
- Scripts: `/etc/restoredefaults.sh`, `/usr/local/lib/restoredefaults.sh` in the unpacked rootfs
- Full command/priv catalog: [advantech_ASMB787-command-table.md](advantech_ASMB787-command-table.md)
