# BMC Generations — Dell iDRAC product ID map

Reference for the `Manufacturer Generation` field that `zipmi mc info` prints.
The label comes from `guess_bmc_generation((iana, product_id))` in
`zipmi/consts.py`. This doc explains where the labels come from, what the
distinctions mean, and where the heuristic falls short.

## Where the field comes from

`Get Device ID` (NetFn 0x06, Cmd 0x01) is a session-less standard IPMI
command. Its response carries a 3-byte **Manufacturer ID** (IANA Enterprise
Number — Dell = 674) and a 2-byte **Product ID**. The tuple
`(manufacturer, product_id)` identifies the BMC family.

zipmi looks up that tuple in a hand-maintained map (`BMC_GENERATION`) and
prints either an exact label (e.g. `iDRAC6 (Monolithic)`) or an inferred
label suffixed with `(guess)`.

## Dell product ID table

| Product ID | Label printed by `mc info` | Form factor                  | Example hardware              |
|-----------:|----------------------------|------------------------------|-------------------------------|
| `0x0100`   | `iDRAC6 (Monolithic)`      | rack / tower                 | PowerEdge R710, T710, R610   |
| `0x0101`   | `iDRAC6 Modular`           | blade                        | PowerEdge M610, M710          |
| `0x0102`   | `iDRAC7 (Monolithic)`      | rack / tower                 | PowerEdge R720, T620          |
| `0x0103`   | `iDRAC7 Modular`           | blade                        | PowerEdge M620, M820          |
| `0x0200`   | `iDRAC8`                   | rack / tower                 | PowerEdge R730, T630          |
| `0x0201`   | `iDRAC8 Modular`           | blade                        | PowerEdge M630, FC630         |
| `0x0300`   | `iDRAC9`                   | rack / tower                 | PowerEdge R740, T640, R640   |
| `0x0301`   | `iDRAC9 Modular`           | blade chassis (MX7000)       | PowerEdge MX740c, MX840c      |
| `0x0400`   | `iDRAC10`                  | rack / tower                 | PowerEdge R770/R670 (16G+)    |

Unknown product IDs whose **high byte** matches a known family fall through
to a `(guess)` label: e.g. `0x02ff` → `iDRAC8 (guess)`.

## Monolithic vs modular — what differs

The two form factors run **separate firmware images** with **different OEM
dispatch tables**. From an attacker / fuzzer perspective they are distinct
targets even when they share an IPMI generation.

### Monolithic (rack / tower)

- **One server, one BMC, one chassis.**
- BMC has direct PCIe / I2C / LPC paths to a single host motherboard.
- OEM cmd surface is what's documented in `dell/fullfw-ipmi-commands.md` and
  what `dell_generated.py` covers (192 entries from T710 / iDRAC6 1.70).
- This is what zipmi's Dell support has been live-verified against.

### Modular (blade)

- Up to 16 blades share a chassis enclosure: **M1000e**, **VRTX**, or
  **MX7000**.
- Each blade has its own iDRAC; the chassis adds a **CMC (Chassis
  Management Controller)** that arbitrates shared resources.
- Modular firmware adds OEM commands the monolithic version doesn't need:
  - **CMC ↔ iDRAC bridging** — chassis-level cmds proxy through the
    blade BMC. See `CmdCMCActivateSession` in
    `idrac9-firmware/IPMI_COMMAND_ENUMERATION.md` (`libmodular.so`).
  - **Shared infrastructure** — fabric / IO modules / shared PSU /
    shared cooling cmds.
  - **Blade slot identity** — each blade reports which bay it occupies.
    `CmdGetBladeID area` (NetFn 0x30, cmd 0x18) appears in the Dell
    iDRAC6 dispatch table but is stubbed (`0xC1`) on monolithic
    firmware — meaningful only on a blade.
  - **`CmdSendBladeCPUThrottle`** — blade chassis can throttle a peer
    blade. Modular-only.
- Larger pre-auth surface, more inter-blade trust assumptions, generally
  more interesting bug substrate.

zipmi's monolithic dispatch tables **do not all apply** to a modular target.
A separate RE pass on a modular firmware image would be needed before
`fuzz sweep` against an M-series blade can be trusted.

## Other vendors

The `BMC_GENERATION` map is currently Dell-only. Other vendors:

- **Supermicro** — single BMC IPMI core across product lines; product ID
  varies by chip family (Aspeed AST2400/2500/2600) more than by chassis.
  Generation guess returns `unknown` for now.
- **HP iLO** — BL-series (blade) vs DL-series (rack) sometimes diverge but
  iLO version is the dominant axis. Not yet mapped.
- **Lenovo XClarity** — ThinkSystem rack vs Flex blade. Not yet mapped.

## Provenance + caveats

Dell has never published a definitive `(product_id) → marketing name` map.
The table above is assembled from:

- Field observation (your T710 reports `0x0100` — that's the anchor).
- Cross-referencing the **iDRAC User's Guide for Modular Servers**
  (separate publication from the monolithic guide) which confirms the
  modular firmware is a distinct image.
- ipmitool issue trackers + Dell community forum threads where users
  posted `product=0x...` and identified the host model.
- Inference from the high-byte family pattern (`0x01xx`, `0x02xx`,
  `0x03xx`).

**Therefore the `(guess)` suffix is not cosmetic.** If you see it, treat
the generation label as a hint, not a fingerprint. Confirm by reading the
firmware revision (`zipmi mc info`'s `Firmware Revision` field) or the
Dell service tag from the host BIOS.

## Updating the map

When a new generation ships (iDRAC11 etc.) or a new product ID surfaces
in the wild:

1. Add the `(iana, product_id) → label` entry to
   `BMC_GENERATION` in `zipmi/consts.py`.
2. Add a row to the Dell product ID table above (this file).
3. Add a row to `tests/unit/test_bmc_generation.py` exercising it.
4. The `scripts/check_doc_sync.py` guard verifies every value in
   `BMC_GENERATION` appears somewhere in `docs/bmc-generations.md` —
   forgetting step 2 will block the commit.
