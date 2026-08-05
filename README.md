# linuxevent-catalogue

A structured catalogue of Linux security & system event IDs — the Linux
counterpart to [`Winevent-catalogue`](https://github.com/adamliq/Winevent-catalogue).
Covers the Linux Audit Framework (`auditd`/kernel audit — authentication,
account management, privilege use, process execution, file access, kernel
modules, SELinux/AppArmor, netfilter), SSH protocol-level session events,
and systemd/journald (unit lifecycle, service failures, session management,
boot/shutdown, time changes, the journal itself).

This is a curated **seed catalogue** (61 events), not an exhaustive one —
Windows' Event ID space is large enough that the source repo's bulk ETW
manifest import alone added thousands of rows; Linux has no equivalent
single exhaustive registry to import from, so this repo instead prioritizes
breadth of coverage across subsystems with every event double-checked
against a primary source, over raw row count. It's built to extend the same
way the Windows repo was: add rows to `data/events.csv`, regenerate
`events.json` and the field schema, done.

## Where Linux event IDs come from

Windows assigns every event a single numeric Event ID per provider. Linux
has no one universal equivalent, so this catalogue uses whichever *real,
verifiable* numeric identifier a given event actually carries on the wire,
and is explicit in each event's `log` field about which scheme is in play:

- **`audit/*` events** (the majority of the catalogue) use the numeric
  `type=` code from the kernel audit subsystem — e.g. `1123` for `USER_CMD`
  (a sudo command execution). These are the same codes any admin sees by
  running `ausearch --raw` instead of the default interpreted output, and
  they were checked against `include/uapi/linux/audit.h` in the upstream
  Linux kernel source (not guessed from memory) before being used here.
  Grouped into four logs by the numeric range those codes fall in:
  `audit/USER` (1100–1199, PAM/account/session accounting — this range also
  covers boot/shutdown and service start/stop, which the kernel treats as
  ordinary userspace-reported messages), `audit/DAEMON` (1200–1203, auditd
  self-reporting), `audit/SYSCALL` (1300–1399, syscall/exec/module/netfilter
  auditing), and `audit/MAC` (1400–1499, SELinux and AppArmor).
- **`ssh/protocol` events** use the numeric `SSH_DISCONNECT_*` reason code
  from RFC 4253 §11.1 — sshd actually prints this number in its own log
  line (`Received disconnect from ⋯ port ⋯:11: ⋯`), so it's a genuine
  identifier from the wire protocol, not an invented one. Verified against
  both the RFC and OpenSSH's own `ssh2.h`.
- **`systemd/journal` events** use the real `MESSAGE_ID` UUID from
  systemd's own message catalog (`catalog/systemd.catalog.in` upstream) —
  the field journald actually stores and that `journalctl MESSAGE_ID=…`
  filters on. This is the closest Linux analogue to a numeric Windows Event
  ID for anything routed through systemd/journald rather than the kernel
  audit subsystem (unit lifecycle, logind sessions, boot milestones, time
  changes, the journal service itself).

One deliberate, documented overlap: SELinux and AppArmor denials **both**
use audit type `1400` (`AVC`) — that's not an error in this catalogue, it's
how the kernel audit subsystem actually works; the two are told apart by
message content (`avc:  denied` vs `apparmor="DENIED"`), not by the type
code. Both get their own row here (same `event_id`, different `source`/
`category`) so each is independently searchable.

Everything else — a plain kernel dmesg line with no registered ID, a bare
NetworkManager INFO message — was left out of this seed rather than given a
made-up number, the same discipline the Windows repo applied when it
flagged low-confidence entries instead of guessing.

## Contents

- `data/events.csv` / `data/events.json` — the main catalogue, one row per
  `(event_id, log, category, subcategory)` combination, with the same
  column shape as `Winevent-catalogue`:
  - `event_id` — see "Where Linux event IDs come from" above.
  - `log` — `audit/USER`, `audit/DAEMON`, `audit/SYSCALL`, `audit/MAC`,
    `ssh/protocol`, or `systemd/journal`.
  - `source` — the specific program/component that generated the record
    (e.g. `sudo`, `sshd (pam_unix)`, `kernel (SELinux)`, `systemd-logind`).
  - `category` / `subcategory` — a GPO-style grouping mirroring the Windows
    catalogue's taxonomy: Account Logon, Logon/Logoff, Account Management,
    Privilege Use, Detailed Tracking, Object Access, Policy Change, System,
    Mandatory Access Control, Network, Service Management.
  - `description` — what the event means.
  - `sample` — a representative example in a consistent fictional
    environment (`prod.example.org` domain, hosts like `web01`/`bastion01`,
    users `jsmith`/`mchen`/`rjones`, RFC 5737 documentation IP ranges).
    Formatted as an Event-Viewer-style header block (Log Name / Source /
    Event ID / Level / Host / Description) followed by the record's real
    field content — field names and values are accurate to how the
    underlying tool actually logs them, but lines are wrapped for
    readability rather than reproduced as the single unbroken line a raw
    `audit.log`/journal entry actually is.
  - `reference` — a short pointer to related tooling or a companion record.
  - `how_to_collect` — which subcategory (from
    `data/reference/audit_configuration.csv`) must be configured to
    generate this event; most are automatic once the relevant subsystem
    (auditd, SELinux/AppArmor, systemd) is simply running.
  - `sample_type` — always `illustrative` in this seed: every sample is a
    representative example built for a consistent fictional environment,
    not a real capture (there's no source notebook of real captures behind
    this repo the way there was for `Winevent-catalogue`).
  - `mitre_techniques` — MITRE ATT&CK technique ID(s), semicolon-separated,
    where a mapping is genuinely warranted — left blank on purely
    operational/diagnostic events (service lifecycle, journal housekeeping)
    the same way the Windows repo left it blank rather than force a stretch
    mapping.
  - `priority_signal` — `Yes` on events curated as classic high-value
    security-monitoring signals (privilege escalation, log/audit tampering,
    MAC denials, brute-force indicators, kernel module loads, group
    membership changes, and similar). **Unlike** `Winevent-catalogue`'s
    `acsc_priority_log` field, this is this repo's own editorial curation —
    ASD/ACSC's "Priority logs for SIEM ingestion" guidance is Windows/AD
    specific, and no equivalent named, sourced Linux guidance document was
    substituted for it. Treat it as a reasonable starting point for
    alerting, not a citation.
  - `nist_800_53_au` — NIST SP 800-53 Audit and Accountability (AU) control
    ID(s): `AU-9` (Protection of Audit Information) for log/audit-tampering
    events, `AU-8` (Time Stamps) for the clock-change event, `AU-4` (Audit
    Storage Capacity) alongside `AU-9` for journal rate-limit suppression,
    and `AU-2, AU-3, AU-12` (the standard "what to audit and how to
    generate it" triad) applied at the subcategory level via
    `data/reference/audit_configuration.csv` — not a substitute for a full
    compliance assessment.
  - `field_schema` — a structured map of the fields inside that event's
    `sample`, grouped the way the real record does (e.g. `process`,
    `subject`, `message`/`record` for an audit event), with each leaf
    giving that field's type (`string`, `integer`, `hex`, `enum`, `ip`,
    `path`, `principal`, `list<string>`, `guid`). Hand-built per event for
    this seed (there's no automatic sample-text parser here yet, unlike the
    generic parser `Winevent-catalogue` built once it had thousands of rows
    to run one over) but follows the exact same shape and intent. In
    `events.json` this is a nested object; in `events.csv` it's the same
    structure serialized as a JSON string.

- `data/reference/audit_configuration.csv` / `.json` — how to configure
  each subcategory: the config file/command, the steps, the event IDs it
  produces, a reference URL where available, and its NIST 800-53 AU
  mapping. See `docs/audit-configuration-guide.md` for the readable
  version.
- `data/reference/audit_record_types.csv` / `.json` — 64 `AUDIT_*` numeric
  message type codes from the kernel's `include/uapi/linux/audit.h`,
  spanning the command/control, daemon, user-accounting, syscall, and MAC
  ranges — this is the field this catalogue uses as `event_id` for every
  `audit/*` log, browsable as a standalone decoder the way
  `ntstatus_codes.csv` works for the Windows repo.
- `data/reference/pam_result_codes.csv` / `.json` — the 22 most relevant
  Linux-PAM return codes (of 32 total) from `_pam_types.h`, seen (as a
  symbolic name) in the `res=`/error fields of USER_AUTH, USER_ACCT, and
  USER_ERR audit records.
- `data/reference/linux_capabilities.csv` / `.json` — a curated 27-capability
  subset (of 41 total) of the `CAP_*` bits from
  `include/uapi/linux/capability.h` — the ones most relevant to security
  monitoring (privilege boundaries, MAC override, audit control, module
  loading, and similar) — each one bit position in the
  `cap_pe`/`cap_pp`/`cap_pi` hex masks of a CAPSET audit record (event ID
  1322).
- `data/reference/errno_codes.csv` / `.json` — a curated 35-code subset of
  the standard Linux `errno.h` values, seen negated in the `exit=` field of
  a failed SYSCALL record (event ID 1300) — narrower than
  `Winevent-catalogue`'s full 1,795-code NTSTATUS table because Linux's
  errno space is itself much smaller (~134 standard codes total) and this
  is the frequently-seen subset, not the exhaustive list.
- `data/reference/ssh_disconnect_codes.csv` / `.json` — all 15
  `SSH_DISCONNECT_*` reason codes from RFC 4253 §11.1, the exact set the
  `ssh/protocol` log's `event_id` is drawn from.
- `data/reference/systemd_message_catalog.csv` / `.json` — 15 real
  `MESSAGE_ID` UUIDs and their catalog subjects/descriptions, sourced from
  systemd's own `catalog/systemd.catalog.in` — the exact set the
  `systemd/journal` log's `event_id` is drawn from.
- `data/reference/mitre_attack_mapping.csv` / `.json` — 23 technique↔event
  associations covering the subset of ATT&CK techniques genuinely relevant
  to this catalogue's events (valid accounts, brute force, privilege
  escalation via sudo/capabilities, account manipulation, rootkit/kernel
  module persistence, log tampering, MAC-policy evasion, firewall
  tampering, container/host escape via MAC denial).
- `docs/event-log-operations.md` — `ausearch`/`aureport`/`journalctl`
  snippets for querying, exporting, and clearing audit/journal logs,
  including a working example for auditing user account creation (event ID
  1114) across a fleet over SSH.
- `docs/audit-configuration-guide.md` — how to actually configure `auditd`,
  PAM, SELinux/AppArmor, and systemd to collect each event: the config
  path or command to run, step-by-step instructions, and the event IDs
  each setting produces.

## Web lookup

`index.html` is a self-contained (no build step, no external requests)
lookup page — the same design as `Winevent-catalogue`'s, scaled down to
match this repo's smaller log/category space: search all 61 events by ID
or keyword; filter by Log or Category via searchable multi-select
comboboxes (3 log families — `audit`, `ssh`, `systemd` — each with a
handful of sub-logs, so the plain grouped-combobox approach the Windows
repo already uses for its 188 logs works here without any further UI work);
toggle to show only curated priority-signal events; active filters surface
as removable chips above the results. View full detail — description,
sample log text, field schema, MITRE ATT&CK mapping, and how-to-collect
configuration steps — plus inline reference tables where they're directly
relevant to the selected event (PAM result codes on credential-validation
events, the capabilities table on the CAPSET event, common errno codes on
the SYSCALL event, the full SSH disconnect table on any `ssh/protocol`
event). A Reference tables tab covers all 8 reference tables with the same
single-search-filters-everything, sticky-jump-nav, height-capped-scrolling,
collapsed-by-default-accordion behavior as the Windows repo's Reference
tab. Open it directly in a browser.

## Source & verification

Unlike `Winevent-catalogue` (extracted from a personal Windows Server
administration notebook of real captures), this repo has no equivalent
source of real log captures to draw from, so every event's *content*
(descriptions, field names, sample values) is a representative
`illustrative` example rather than a real capture — but every event's
*identity* (its numeric/UUID `event_id` and the field vocabulary that
identifier implies) was checked against a primary source before being
used, not written from memory:

- **`AUDIT_*` type codes** — fetched and cross-checked against
  `include/uapi/linux/audit.h` in the `torvalds/linux` kernel source
  (command/control, daemon, user-accounting, syscall, and MAC ranges).
  AppArmor's kernel module (`security/apparmor/include/audit.h`) was also
  checked directly — it does *not* define its own numeric audit message
  type; AppArmor denials go out over the kernel audit socket using the
  same `AUDIT_AVC` (1400) type SELinux uses, which is why both share an
  `event_id` in this catalogue.
- **PAM return codes** — fetched from Linux-PAM's own
  `libpam/include/security/_pam_types.h`.
- **Linux capabilities** — fetched from the kernel's
  `include/uapi/linux/capability.h`.
- **errno codes** — fetched from the kernel's
  `include/uapi/asm-generic/errno-base.h` and `errno.h`.
- **SSH disconnect codes** — cross-checked against both RFC 4253 §11.1 and
  OpenSSH's own `ssh2.h` (`SSH2_DISCONNECT_*` constants), which agreed
  exactly.
- **systemd message catalog UUIDs** — fetched from
  `catalog/systemd.catalog.in` in the `systemd/systemd` source.

The category/subcategory taxonomy, event selection, sample content, field
schemas, MITRE/NIST mappings, and priority-signal curation are original
editorial work for this repo, built to mirror `Winevent-catalogue`'s
structure and depth rather than translated from any single existing Linux
logging reference.
