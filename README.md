# linuxevent-catalogue

A structured catalogue of Linux security & system event IDs — the Linux
counterpart to [`Winevent-catalogue`](https://github.com/adamliq/Winevent-catalogue).
Covers the Linux Audit Framework (`auditd`/kernel audit — authentication,
account management, privilege use, process execution, file access, kernel
modules, SELinux/AppArmor, netfilter, package management, removable
media, cron persistence, dynamic-linker injection, container
administration, PKI/trust-store and SSH-host-key tampering, Kerberos/SSSD
identity-provider config), SSH protocol-level session events, and
systemd/journald (unit lifecycle, service failures, session management,
boot/shutdown, time changes, the journal itself). Also cross-referenced
against the Australian Cyber Security Centre's Information Security
Manual (ISM) via the `xccdf_org.ssgproject.content_profile_ism_o` SCAP
profile (`acsc_ism_control`) and against CIS RHEL 9 Benchmark v2.0.0 /
DISA RHEL 9 STIG via the repo owner's supplied master rule catalogue
(`cis_control`/`disa_stig_id`) — see below.

This is a curated **seed catalogue** (77 events), not an exhaustive one —
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
    membership changes, and similar). This remains this repo's own
    editorial curation, not sourced from a named guidance document — see
    `acsc_ism_control` below for the field that *is* sourced.
  - `acsc_ism_control` — ID(s) of the Australian Cyber Security Centre
    Information Security Manual (ISM) OFFICIAL-level control(s) this event
    helps satisfy, semicolon-separated, blank otherwise. Unlike
    `priority_signal`, this one **is** genuinely sourced: from
    `controls/ism_o.yml` in
    [`ComplianceAsCode/content`](https://github.com/ComplianceAsCode/content) —
    the project that maintains the `xccdf_org.ssgproject.content_profile_ism_o`
    SCAP profile — fetched directly from the upstream repo rather than
    guessed. 33 of this catalogue's 77 events are tagged, covering 4 of the
    profile's 41 controls (the ones whose rule list actually corresponds to
    an auditing mechanism this catalogue documents; the other 37 controls
    are about password policy, MFA, SSH hardening, antivirus, and similar,
    outside this catalogue's event-log scope). Mapped at the subcategory
    level, the same granularity `nist_800_53_au` already uses — and in a
    couple of places, the profile's specific SSG rule uses a different
    underlying mechanism than the event it's tagged on (e.g. control 0582
    includes `audit_rules_session_events_utmp/btmp/wtmp`, which are `auditd`
    watches on the traditional `/var/log/wtmp`/`btmp` accounting files, a
    different mechanism from the PAM `USER_START`/`USER_END` records this
    catalogue's Logon/Logoff events actually document) — both serve the
    control's stated objective, but that's a real distinction, not a false
    equivalence, so it's called out here rather than left implicit. See
    `data/reference/acsc_ism_controls.csv` for the full control list with
    its complete related-rules text, and the "ACSC ISM OFFICIAL controls"
    section of the Reference tables tab.
  - `cis_control` / `disa_stig_id` — CIS RHEL 9 Benchmark v2.0.0 §6.3.3
    control ID(s) and DISA RHEL 9 STIG `RHEL-09-654xxx` ID(s), mined from
    `docs/auditd-rules-master-reference.md` — the same document
    `data/reference/auditd_rules.csv` is parsed from — at the (category,
    subcategory) level, same as `acsc_ism_control`, plus one event-level
    override (the pam_faillock lockout event gets `RHEL-09-654250`
    specifically rather than its subcategory's blanket tag, since that's
    exactly what that STIG ID is about). Populated on 25 events (`cis_control`)
    and 21 events (`disa_stig_id`) of the 77 — only where a section of the
    master reference gives an *exact* identifier and this catalogue's own
    event mechanism plausibly corresponds to that section's rule (e.g.
    SELinux/AppArmor AVC *denial* events are deliberately **not** tagged
    with §20's `6.3.3.14`, because that control covers auditing changes to
    the MAC *policy/config* — this catalogue's separate MAC Policy
    subcategory — not AVC denial records, which §20 doesn't actually
    cover). Sections that only say "aligns with 30-stig.rules" without a
    numbered ID contribute a `cis_control` but leave `disa_stig_id` blank,
    rather than citing a non-exact alignment as if it were a verified ID.
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
- `data/reference/acsc_ism_controls.csv` / `.json` — the 4 ACSC ISM OFFICIAL
  controls (of the `xccdf_org.ssgproject.content_profile_ism_o` profile's 41
  total) whose ComplianceAsCode rule list corresponds to this catalogue's
  events, each with its title, applicability level, the related SSG rule
  names, and a link to the ISM itself — the source for `acsc_ism_control`
  above.
- `docs/event-log-operations.md` — `ausearch`/`aureport`/`journalctl`
  snippets for querying, exporting, and clearing audit/journal logs,
  including a working example for auditing user account creation (event ID
  1114) across a fleet over SSH.
- `docs/audit-configuration-guide.md` — how to actually configure `auditd`,
  PAM, SELinux/AppArmor, and systemd to collect each event: the config
  path or command to run, step-by-step instructions, and the event IDs
  each setting produces.
- `docs/auditd-rules-master-reference.md` — a much broader (321-rule,
  88-section) `auditd` rule catalogue supplied by the repo owner, covering
  CIS RHEL 9 Benchmark v2.0.0 §6.3.3, DISA RHEL 9 STIG (`RHEL-09-654xxx`),
  ACSC ISM outcome alignment, and SCAP/ComplianceAsCode integration. Its
  ~88 sections were also used as a roadmap to add 16 new curated events
  (file deletion, DAC permission/ownership changes, extended attributes,
  filesystem mounts, removable media, cron persistence, dynamic-linker
  injection, package management, DNS/SSH-host-key/PKI-trust-store
  tampering, container administration, Kerberos/SSSD identity-provider
  config, `ptrace`-based process injection, and namespace manipulation) —
  each event's `reference` field cites the exact corresponding
  `auditd_rules.csv` `rule_id`(s). Some sections remain uncovered by a
  curated event (Kubernetes/OpenShift specifics, LDAP, IPA beyond what
  the shared Kerberos/SSSD config watch covers, and the more exotic
  system-administration sections) — this is still a seed, not a claim of
  full coverage of the master reference. This document is the single
  source of truth for the Auditd Rules tab and
  `data/reference/auditd_rules.csv`/`.json` below —
  `build.py` parses it directly, so editing the markdown and re-running
  the build regenerates both. It is **not** wired into the main
  `events.csv`/`.json` catalogue — its CIS and DISA STIG identifiers are
  not reflected in `acsc_ism_control` or any other event field; it's a
  separate, much larger rule-level catalogue that stands on its own.
- `docs/auditd-rules-log-examples.md` — 36 real
  `/var/log/audit/audit.log` example blocks supplied by the repo owner
  (one or more per major rule category), each showing the actual
  multi-record output — `SYSCALL`/`PATH`/`CWD`/`EXECVE`/`PROCTITLE`/
  `OBJ_PID` sharing one timestamp:serial — a matching rule produces.
  `build.py` parses this file too and attaches each example to every
  `auditd_rules.csv` row whose `audit_key` matches the example's own
  `key="..."` value (not by section number, since a few keys — e.g.
  `network_config` — are genuinely defined identically in two different
  sections of the master reference, and key-matching correctly surfaces
  the example on all of them). One exact mismatch surfaced by this: the
  SSH Security log example was captured with `key="sshd_config"`, but
  every §7 rule in the master reference uses `key="ssh_config"` (no
  "d") — mapped explicitly via a small alias table rather than silently
  merged, and the discrepancy is shown directly on the rendered example
  rather than hidden. 136 of 321 rules end up with at least one attached
  example; the rest (control flags with no `-k`, and categories the log
  examples file doesn't cover) have none — see `log_samples` below.
- `data/reference/auditd_rules.csv` / `.json` — 321 individual `auditctl`
  rules mechanically extracted from `docs/auditd-rules-master-reference.md`
  (every `-w`/`-a always,exit` line in the source, plus each row of its
  five hand-authored per-rule tables), across 83 of the source's 88
  sections (the other 5 are prose-only, with no copy-pasteable rule
  syntax to extract). Columns: `rule_id` (`section-sequence`, e.g.
  `08-03`), `category_no`/`category` (the source's own section numbering),
  `title`, `auditd_rule`, `audit_key`, `description`, `cis_ref`,
  `disa_stig_ref`, `acsc_ism_alignment`, and `form` (`table` — from one of
  the source's 5 per-rule tables, highest fidelity; `code_block` — a rule
  line from a fenced code block; `stig_canonical` — from a "DISA STIG
  canonical form" subsection, the stricter `-a always,exit -F path=...`
  syntax offered as an alternative to the shorthand `-w` form). **`cis_ref`,
  `disa_stig_ref`, and `acsc_ism_alignment` are applied at the section
  level**, matching the granularity the source document itself uses
  (framework references are stated once per section intro, not
  per-rule, except in the 5 tabular sections) — where a section mixes
  several distinct rule groups under one reference (e.g. §8 "sudo and
  Privilege Escalation" states `RHEL-09-654150` once for the whole
  section, covering both the `/etc/sudoers` watch and the unrelated
  `/usr/bin/mount`/`/usr/sbin/reboot` privileged-command rules also filed
  under that section), every rule in that section carries the same
  reference text. Treat these fields as "this rule lives in a
  framework-relevant section," not as a verified per-rule compliance
  citation — the source document's own header says the same about
  itself, and this table inherits that limitation mechanically rather
  than resolving it.

  Each row also carries a `switches_explained` field: every flag in the
  rule (`-w`, `-p`, `-k`, `-a always,exit`, `-S <syscall,...>`, `-F
  <field><op><value>`, `-D`, `-b`, `-f`, `-e`, `-i`) tokenized in order,
  each with a plain-English explanation — generated by a small,
  deterministic auditctl-syntax decoder in `build.py` (checked against
  `man auditctl`/`man 7 audit.rules`, covering exactly the ~60-term
  vocabulary this dataset actually uses: syscalls, `-F` field names,
  permission letters, architectures, and the two `errno` names it
  filters on — not a general-purpose auditctl parser). In `events.json`-
  style fashion, it's a nested array of `{token, explanation}` objects in
  the JSON file and the same structure JSON-serialized into the CSV
  cell. All 321 rows resolve to a full explanation for every token — see
  the Auditd Rules tab's detail view for the rendered form.

  Each row also carries a `log_samples` field: real
  `/var/log/audit/audit.log` example(s) from
  `docs/auditd-rules-log-examples.md`, attached by exact `audit_key`
  match (136 of 321 rows have at least one). A nested array of `{title,
  log, annotation, key_note}` objects — `annotation` carries the source
  document's own decoded-value notes (e.g. "exit=-13 → EACCES /
  Permission denied") where present; `key_note` flags the one known
  key-spelling mismatch (§7 SSH Security, `sshd_config` in the captured
  log vs. `ssh_config` in the rule) rather than silently smoothing it
  over.
- `data/reference/auditd_fields.csv` / `.json` — 234 entries: every field
  name that can appear in a kernel audit record (`SYSCALL`, `PATH`,
  `EXECVE`, `AVC`, `USER_*`, and the rest — `auid`, `arch`, `exe`, `cmd`,
  `cap_pe`, `subj`/`obj` SELinux contexts, VM/container resource fields,
  crypto fields, printer fields, and more), each with its value `format`
  (numeric, numeric (hex), encoded, alphanumeric, alphabet, or a
  combination) and a plain-English `explanation`. Supplied by the repo
  owner as a merge of the fields already implicit in this catalogue's own
  samples plus the official Linux Audit field dictionary. Powers the
  Fields submenu under the Auditd Rules tab, described below.

  Each row also carries a Splunk CIM (Common Information Model) enrichment,
  supplied by the repo owner: `cim_potential_name` (the nearest CIM field
  name or names), `supported_cim_field` (which of those, if any, Splunk's
  CIM actually recognises — some potential names have no directly
  supported CIM field), `cim_data_model_category` (which CIM data
  model(s) the field falls under — Authentication, Change, Endpoint,
  Network_Traffic, Intrusion_Detection, Inventory), and `splunk_app`
  (which Splunk app/TA maps the field out of the box —
  `Splunk Add-on for Linux`, the community `TA-linux_auditd`, `custom`
  for a local `FIELDALIAS`/`EVAL`, or a slash-separated combination). The
  source table itself grouped several related fields under one row (e.g.
  `cap_*`, `obj`/`obj_*`, `subj`/`subj_*`, `new-*`/`old-*`) — `build.py`
  expands each group against the actual field names already in
  `AUDITD_FIELDS` rather than guessing new ones, and a later specific
  entry always wins over an earlier wildcard one on overlap (e.g.
  `old_prom`, which the `old-*`/`old_*` wildcard would otherwise put
  under "Change", is pinned to its own "Network_Traffic" entry instead).
  118 of the 234 fields have a CIM enrichment; the rest were not covered
  by the source table and are left blank in all four columns — distinct
  from the source table's own explicit `"—"` ("no known mapping" for a
  field it did consider, e.g. `arch`, `data`, `items`, `list`, `msg`).
- `data/reference/auditd_record_type_names.csv` / `.json` — 159 entries:
  every value the `type=` field can take at the start of a record in
  `/var/log/audit/audit.log` (`SYSCALL`, `PATH`, `AVC`, `USER_*`,
  `DAEMON_*`, `APPARMOR_*`, `MAC_*`, `CRYPTO_*`, `INTEGRITY_*`, `VIRT_*`,
  and the rest), each with a plain-English explanation, supplied by the
  repo owner. `data/reference/auditd_record_type_ranges.csv` / `.json` —
  the 15 numeric ranges these type names fall into per the kernel audit
  header (`include/uapi/linux/audit.h`) and the audit userspace
  message-type ranges (e.g. `1400–1499` = SELinux, `1500–1599` =
  AppArmor, `2500–2599` = user-space virtualization events).
  `data/reference/auditd_record_type_common.csv` / `.json` — the 10 record
  types most frequently seen in day-to-day `audit.log` analysis, with
  their typical origin (e.g. `SYSCALL`/`PATH`/`CWD`/`EXECVE`/`PROCTITLE`
  from almost every syscall rule, `AVC` from SELinux denials/grants).
  Together these power the Record Types submenu under the Auditd Rules
  tab, described below.
- `data/reference/auditd_commands.csv` / `.json` — 7 entries: the core
  `auditd` tools (`auditctl`, `ausearch`, `aureport`, `auditd`,
  `augenrules`, `autrace`, `audispd`) and their most useful options,
  supplied by the repo owner. Columns: `command`, `purpose`, `sections`
  (a nested array of `{title, code}` command-block groups — e.g.
  `auditctl`'s "File watches"/"Syscall rules"/"Useful filters",
  `ausearch`'s "By key"/"By time"/"By user / process"/etc. — JSON-
  serialized into the CSV cell like `auditd_rules.csv`'s
  `switches_explained`/`log_samples`), and `notes` (free-standing text
  that isn't itself a command, e.g. the `-p` permission-flag legend).
  `audispd` has no dedicated section content in the source. Also powers
  two supplementary static blocks: a 6-step "quick operational
  cheat-sheet" (one block of text rather than rows, so it's kept as a
  single string injected straight into `index.html`'s data blob instead
  of its own reference CSV) and
  `data/reference/auditd_command_related_files.csv` / `.json` — 5 rows
  mapping `/etc/audit/auditd.conf`, `/etc/audit/audit.rules`,
  `/etc/audit/rules.d/`, `/var/log/audit/audit.log`, and
  `/etc/audit/plugins.d/` to their purpose. Together these power the
  Commands submenu under the Auditd Rules tab, described below.

## Web lookup

`index.html` is a self-contained (no build step, no external requests)
lookup page with three tabs.

**Events** — the same design as `Winevent-catalogue`'s, scaled down to
match this repo's smaller log/category space: search all 77 events by ID
or keyword; filter by Log or Category via searchable multi-select
comboboxes (3 log families — `audit`, `ssh`, `systemd` — each with a
handful of sub-logs, so the plain grouped-combobox approach the Windows
repo already uses for its 188 logs works here without any further UI work);
toggle to show only curated priority-signal events, plus a second toggle
for events mapped to an ACSC ISM OFFICIAL control; active filters surface
as removable chips above the results. View full detail — description,
sample log text, field schema, MITRE ATT&CK mapping, ACSC ISM control
link, CIS RHEL 9/DISA STIG IDs where mined, and how-to-collect
configuration steps — plus inline reference
tables where they're directly relevant to the selected event (PAM result
codes on credential-validation events, the capabilities table on the
CAPSET event, common errno codes on the SYSCALL event, the full SSH
disconnect table on any `ssh/protocol` event).

**Auditd Rules** — a four-item submenu, **Rules**, **Fields**,
**Record Types**, and **Commands**.

*Rules* is the same search/filter/detail layout applied to all
321 rows of `data/reference/auditd_rules.csv`: a free-text search across
the rule text, title, category, audit key, description, every
CIS/DISA-STIG/ACSC-ISM reference field, every switch's explanation text,
and every attached log example's own text (so searching `6.3.3.8`,
`RHEL-09-654150`, `sudo_config`, "kernel module"/"root privileges" from
an explanation, or `EACCES`/`modprobe` from a real captured log line,
all work), plus a searchable multi-select Category combobox ordered by
the source document's own section numbering (1–88) rather than
alphabetically. Rows with a real log example carry a **LOG** badge. The
detail view shows the full `auditd_rule` in a code block, then — where
one is attached — a **Log Example** section with the real
`/var/log/audit/audit.log` output (plus any decoded-value annotation and
the one known key-spelling discrepancy, where it applies), then a
**Switches & Arguments Explained** section breaking the rule into one
card per flag with its plain-English meaning (e.g. `-F auid>=1000` → why
`auid` rather than `uid` matters for attributing an action through
`su`/`sudo`, and why 1000 specifically), alongside its CIS/STIG/ACSC
fields and a source note pointing back to the originating section of
`docs/auditd-rules-master-reference.md` (and, when present, the log
example's source in `docs/auditd-rules-log-examples.md`).

*Fields* is a single searchable table over all 234 rows of
`data/reference/auditd_fields.csv` — field name, value format,
explanation, and its Splunk CIM enrichment (potential CIM name,
supported CIM field, CIM data model, and mapping Splunk app/TA) —
filtered live as you type across all seven columns (so searching
"SELinux" surfaces every `subj_*`/`obj_*`/`*context*` field at once, and
searching "Intrusion_Detection" or "TA-linux_auditd" filters by the CIM
columns alone). Blank CIM cells mean the field wasn't covered by the
enrichment; an explicit "—" means it was considered and has no known
mapping.

*Record Types* is a searchable table over all 159 rows of
`data/reference/auditd_record_type_names.csv` — the value the `type=`
field takes at the start of every audit record, and what it means —
filtered live by name or explanation, plus two static reference tables
shown alongside it: the 15 numeric ranges these type names fall into per
the kernel audit header (`data/reference/auditd_record_type_ranges.csv`)
and the 10 record types most frequently seen in day-to-day log analysis
with their typical origin
(`data/reference/auditd_record_type_common.csv`), and a closing tip on
using `ausearch -m` to see the exact list recognised by the installed
audit package.

*Commands* is a list/detail view (the same layout as *Rules*, scaled to 7
rows) over `data/reference/auditd_commands.csv`/`.json` — the core
`auditd` tools (`auditctl`, `ausearch`, `aureport`, `auditd`,
`augenrules`, `autrace`, `audispd`) and their most useful options,
supplied by the repo owner. Each row's `sections` field is a nested array
of `{title, code}` command-block groups (e.g. `auditctl`'s "Status",
"File watches", "Syscall rules", "Useful filters"; `ausearch`'s "By
key", "By time", "By user / process", "By syscall / success", and more)
— JSON-serialized into the CSV cell the same way `auditd_rules.csv`'s
`switches_explained`/`log_samples` are. Search matches a command name, a
section title, an option string inside a code block (e.g. `-ts today`,
`--format csv`), or the row's free-standing `notes` (e.g. auditctl's
`-p` permission-flag legend). `audispd` has no dedicated section content
in the source — its detail view says so explicitly rather than
rendering an empty block. Below the list/detail split, two always-visible
reference blocks: a **Quick operational cheat-sheet** (six common
day-to-day command sequences,
`DATA.auditd_command_cheatsheet` client-side) and a **Related files**
table (`data/reference/auditd_command_related_files.csv` — 5 rows:
`auditd.conf`, `audit.rules`, `rules.d/`, `audit.log`, `plugins.d/`).

**Reference tables** — covers all 9 accordion-style reference tables
(`auditd_rules` gets its own dedicated tab instead, given its size) with
the same single-search-filters-everything, sticky-jump-nav,
height-capped-scrolling, collapsed-by-default-accordion behavior as the
Windows repo's Reference tab.

Open `index.html` directly in a browser.

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
- **ACSC ISM controls** — fetched from `controls/ism_o.yml` in
  `ComplianceAsCode/content`, the control-to-rule mapping backing the
  `xccdf_org.ssgproject.content_profile_ism_o` SCAP profile; cross-checked
  against the profile definition itself
  (`products/rhel9/profiles/ism_o.profile`) to confirm it extends the
  Essential Eight baseline and selects `ism_o:all` minus a documented
  exclusion list. The rendered, published HTML guide for this profile
  (`static.open-scap.org/ssg-guides/ssg-rhel9-guide-ism_o.html`) would have
  been a good second, independent cross-check but was unreachable from
  this environment (blocked the fetch outright) — flagging that rather
  than skipping the caveat silently.

The category/subcategory taxonomy, event selection, sample content, field
schemas, MITRE/NIST mappings, ACSC ISM subcategory-level tagging, and
priority-signal curation are original editorial work for this repo, built
to mirror `Winevent-catalogue`'s structure and depth rather than
translated from any single existing Linux logging reference.
