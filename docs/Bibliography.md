# Bibliography

Specifications, reference implementations, libraries, and research that zipmi
leaned on. Everything here was **read as a reference** — zipmi's wire code is its
own (see [License](../README.md#license)). Where a source shaped a specific
decoder, the section notes it.

## Primary specifications

- **IPMI — Intelligent Platform Management Interface, v2.0** (rev 1.1, markup
  Oct 2013), Intel / Hewlett-Packard / NEC / Dell.
  The core reference for RMCP+, RAKP, cipher suites, channels, users, SDR/SEL,
  and the App/Chassis/Storage/Transport command sets. Section citations
  throughout the source (e.g. §13.x RMCP+/RAKP, §22.x channels & users) refer to
  this document.
  <https://www.intel.com/content/www/us/en/products/docs/servers/ipmi/ipmi-second-gen-interface-spec-v2-rev1-1.html>

- **IPMI — Intelligent Platform Management Interface, v1.5** (rev 1.1), Intel et al.
  The legacy LAN session model (Get Session Challenge / Activate Session,
  auth types none/MD2/MD5/straight-password) that zipmi speaks with `-I lan`.
  Intel IPMI spec landing page (both v1.5 and v2.0 PDFs):
  <https://www.intel.com/content/www/us/en/products/docs/servers/ipmi/ipmi-home.html>

- **DCMI — Data Center Manageability Interface Specification, v1.5** (rev 1.0), Intel.
  Backs `zipmi dcmi` (power, thermal, asset tag, identification over the DCMI
  group-extension NetFn).
  <https://www.intel.com/content/www/us/en/products/docs/servers/ipmi/dcmi-v1-5-revision-spec.html>

- **DMTF ASF — Alert Standard Format, v2.0 (DSP0136).**
  Defines RMCP (the UDP/623 framing IPMI-over-LAN rides on) and the RMCP
  presence-ping/pong used by discovery. RMCP+ extends this.
  <https://www.dmtf.org/sites/default/files/standards/documents/DSP0136.pdf>

## Reference implementations (tools)

- **ipmitool** — BSD-3-Clause. The de-facto reference client; zipmi's output and
  by-name UX are cross-checked against it (`mc info`, `user list`, `sol`, `lan
  print`, `chassis`, raw). Note: our `user-matrix` "CbkRestr" is the spec bit
  (restricted-to-callback), the *inverse* of ipmitool's "Callin" column.
  <https://github.com/ipmitool/ipmitool>

- **FreeIPMI** — GPL-3.0. Consulted for parameter tables where the spec is terse
  — the serial/modem config parameter numbers (`libfreeipmi/.../ipmi-serial-modem-configuration-parameters-spec.h`)
  informed `zipmi serial`.
  <https://www.gnu.org/software/freeipmi/> · source <https://git.savannah.gnu.org/cgit/freeipmi.git>

- **ipmiutil** — BSD. Its `iserial.c serparams[]` table cross-checked the
  serial/modem config parameter labels.
  <https://ipmiutil.sourceforge.net/>

- **OpenBMC / phosphor-net-ipmid** — Apache-2.0. The RMCP+ (cipher-suite-17,
  HMAC-SHA256 / AES-CBC-128) target zipmi is validated against; behavior of a
  strict 2.0-only BMC (1.5 dropped, `0xC1` for unimplemented commands).
  <https://www.openbmc.org/> · <https://github.com/openbmc/phosphor-net-ipmid>

## Libraries

- **Scapy** — GPL-2.0. zipmi builds and dissects every IPMI/RMCP packet as Scapy
  layers (`zipmi/scapy_ipmi/`).
  <https://scapy.net/> · <https://github.com/secdev/scapy>

- **pyghmi** — Apache-2.0 (OpenStack). A wonderful, mature IPMI/Redfish library;
  read as an algorithmic reference for packet formats and completion-code
  strings (`zipmi.consts.COMP_CODE` uses pyghmi-style descriptive text). No code
  copied.
  <https://opendev.org/openstack/pyghmi> · docs <https://docs.openstack.org/pyghmi/latest/>

## Security research

- **Dan Farmer — IPMI / BMC security** ("Sold Down the River", penetration test
  papers, the `fish2.com/ipmi` corpus). Context for the RAKP hash-disclosure,
  cipher-0, and anonymous/null-user exposures zipmi surfaces.
  <http://fish2.com/ipmi/>

- **CVE-2013-4786 — IPMI 2.0 RAKP RMCP+ authentication remote password-hash
  disclosure** (H. Moore / Rapid7, D. Farmer). The RAKP-2 HMAC leak zipmi can
  capture (hashcat `-m 7300`).
  <https://nvd.nist.gov/vuln/detail/CVE-2013-4786>
