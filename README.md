<div align="center">

# 🛡️ _ZeroShield DLP - Data Loss Prevention_

### _Find Sensitive Data, Stop It Leaving and Prove It to Your Auditors, Across Laptops, Email, Cloud Apps and Storage_

<img width="365" height="100" alt="Zero-Shield" src="https://github.com/user-attachments/assets/ac395e39-3282-4acd-8534-3097f588c486" />

_ZeroShield DLP, a standalone data loss prevention product from <a href="https://zeroshield.ai">ZeroShield</a>_

## 🚀 [Explore ZeroShield Solutions](https://zeroshield.ai)
</div>

## Table of Contents
* [About ZeroShield DLP](#about-zeroshield-dlp)
  * [Key Highlights](#key-highlights)
* [System Architecture](#system-architecture)
  * [Architecture diagrams](#architecture-diagrams)
* [Core Modules](#core-modules)
  * [1. Detection Engine](#1-detection-engine)
  * [2. Policies & Enforcement](#2-policies--enforcement)
  * [3. Groups](#3-groups)
  * [4. Endpoint DLP](#4-endpoint-dlp)
    * [Block Screen Capture](#block-screen-capture)
  * [5. Data in Motion](#5-data-in-motion)
  * [6. Data at Rest](#6-data-at-rest)
  * [7. Incident Management & Investigation](#7-incident-management--investigation)
  * [8. Connections](#8-connections)
  * [9. Dashboards, Reports & Compliance](#9-dashboards-reports--compliance)
  * [10. Data Retention & Export](#10-data-retention--export)
* [Endpoint Agent & Deployment](#endpoint-agent--deployment)
  * [Supported Systems](#supported-systems)
  * [Installation & Enrolment](#installation--enrolment)
  * [Automatic, Signed Updates](#automatic-signed-updates)
  * [Self-Protection & Resilience](#self-protection--resilience)
* [Organisations, Users & Roles](#organisations-users--roles)
* [Security & Data Protection](#security--data-protection)
* [Measured Performance](#measured-performance)
* [Governance & Compliance](#governance--compliance)
* [Recommended Rollout](#recommended-rollout)
* [Target Users & Example Scenarios](#target-users--example-scenarios)
* [Use Cases](#use-cases)
* [Frequently Asked Questions](#frequently-asked-questions)
* [Complete Product Video](#complete-product-video)
* [Support](#support)

---

## About ZeroShield DLP

[**ZeroShield DLP**](https://zeroshield.ai) is a standalone data loss prevention product from ZeroShield. It finds sensitive data (Aadhaar and PAN numbers, payment cards, bank details, passwords and API keys, your customer lists and your confidential documents), decides whether to **allow**, **warn** or **block**, carries out the action your policy calls for, and records an incident with masked evidence. It has its own console, sign-up, user management and roles, so no other ZeroShield product is needed.

It covers the three places data lives with **one detection engine, one set of policies and one console**:

| | Where | What is checked |
| :--- | :--- | :--- |
| 💻 **Endpoints** | Employees' laptops and desktops | Files saved and copied, clipboard, USB drives, printing, screenshots and screen recordings, network uploads |
| 📤 **Data in motion** | Data being sent | Outgoing email, Google Drive and OneDrive sharing, uploads through your web proxy, FTP and SFTP |
| 🗄️ **Data at rest** | Data being stored | Amazon S3, Azure Blob Storage, Google Cloud Storage, PostgreSQL, MySQL, SQL Server, Oracle and Windows file shares |

ZeroShield DLP is built for organisations that answer to India's **Digital Personal Data Protection (DPDP) Act 2023** and RBI guidelines, as well as **PCI DSS**, **GDPR**, **HIPAA**, **ISO 27001** and **SOC 2**. Indian identifiers are first-class: Aadhaar numbers are validated with the Verhoeff checksum, GSTINs with their check character and PANs with their structure rules, alongside IFSC codes, UPI IDs and Indian passport and mobile numbers.

### Key Highlights

* 🔍 **One engine for every channel**: the same detectors, customer lists and policies apply on laptops, in email, in cloud apps, on the network and in storage.
* ✅ **Checksum-validated detection**: card numbers must pass the Luhn check and Aadhaar numbers the Verhoeff check, so invoice numbers and random digit runs do not raise alarms.
* 🧬 **Your own data, never stored in clear**: upload customer lists (Exact Data Match) and confidential documents (Indexed Document Match). ZeroShield keeps only salted fingerprints.
* 💻 **Native endpoint agent** for Windows, Linux and macOS, covering files, clipboard, USB, print, screen capture and network.
* 🖼️ **Block screen capture**: one switch stops screenshots and screen recordings on every computer, while video calls keep working.
* 🎯 **Rules for the right people**: limit any rule to chosen groups of people and computers, or leave them out of it.
* ☁️ **No passwords shared for cloud**: Google Workspace and Microsoft 365 connect through admin consent, and Amazon S3 through a read-only role in your own AWS account.
* 🧹 **Reversible clean-up**: quarantine, tombstone, revoke public access or encrypt files in Amazon S3, each with one-click undo.
* 🔒 **Privacy by design**: matched values are masked at the moment of capture. The real card or Aadhaar number is never stored.
* �️ **Retention you choose**: keep endpoint activity for the period you choose, from 30 days to forever, and export it to CSV at any time.
* ⚡ **Live console**: incidents, computers and scans update on their own, with a notice when new incidents arrive.
* �📊 **Audit-ready reporting**: compliance reports for the DPDP Act 2023, PCI DSS v4.0, GDPR and the HIPAA Security Rule, alongside channel coverage and detector health reports.
* 🧩 **Standalone**: its own console, organisation sign-up, user management, roles and sign-in activity log. Nothing else from ZeroShield is required.
* 🏢 **Multi-tenant**: each organisation's users, agents, rules, incidents and data are kept apart by the server, not by the browser.

<p align="center">
  <img src="assets/dlp-overview.png" alt="ZeroShield DLP Overview screen" width="900">
  <br>
  <em>Overview: open incidents, agents online, sensitive findings, the 30-day incident trend and activity per channel</em>
</p>

---

## System Architecture

ZeroShield DLP follows a **Connect → Detect → Enforce → Prove** lifecycle:

1. **Connect**: install the agent on computers, connect email and cloud apps, register storage, group your people and computers, and write policies, all from the console.
2. **Detect**: every file, message, upload, clipboard copy, print job and stored object is checked by the same detection engine.
3. **Enforce**: the policy engine picks the action for the people and computers each rule applies to, and the point of enforcement carries it out: the agent on the computer, the mail filter, your web proxy, the cloud-app connection or the storage scanner.
4. **Prove**: matches are recorded as incidents with masked evidence, and reported per channel and per law for your security team and your auditors.

### Architecture diagrams

**High-level: where data is checked and how the product fits together**

```mermaid
graph LR
    subgraph Org["Your organisation"]
        Agent["ZeroShield agent<br/>Windows · Linux · macOS"]
        Mail["Your mail server"]
        Proxy["Web proxy<br/>Squid · Zscaler · Palo Alto · Fortinet"]
        Suites["Google Workspace<br/>Microsoft 365"]
        Storage["Cloud storage, databases<br/>and file shares"]
    end

    subgraph ZS["ZeroShield DLP"]
        Console["Web console"]
        Gateway["Sign-in gateway<br/>sign-in · roles · tenant isolation"]
        DLP["DLP service<br/>detection · policy · incidents · fleet"]
        Workers["Storage scanner"]
    end

    Console --> Gateway
    Gateway --> DLP
    DLP --> Workers
    Agent <-->|"events, policy, signed updates"| DLP
    Mail -->|"may this email leave? (mail filter)"| DLP
    Proxy -->|"may this upload leave? (ICAP)"| DLP
    DLP <-->|"file and mail activity, sharing removal"| Suites
    Workers -->|"scan, clean up, undo"| Storage
```

**Detection pipeline: from content to decision**

```mermaid
flowchart TB
    Input["Content to check<br/>file · email · upload · clipboard<br/>print job · screenshot · stored object"]
    Extract["Text extraction<br/>documents · spreadsheets · archives<br/>OCR for images"]
    Builtin["Built-in detectors<br/>patterns and checksums"]
    EDM["Exact Data Match<br/>your customer lists"]
    IDM["Indexed Document Match<br/>your documents"]
    ML["ML classifier<br/>document types, optional"]
    Merge["One merged verdict<br/>tier · categories · confidence"]
    Policy{"Policy engine<br/>rules · groups"}
    Allow["Allow<br/>let it through"]
    Warn["Warn<br/>tell the person, record it"]
    Enforce["Block · redact · encrypt<br/>quarantine · revoke sharing"]
    Incident["Incident with<br/>masked evidence"]

    Input --> Extract
    Extract --> Builtin & EDM & IDM & ML
    Builtin & EDM & IDM & ML --> Merge
    Merge --> Policy
    Policy -->|"allow"| Allow
    Policy -->|"warn"| Warn
    Policy -->|"block"| Enforce
    Warn --> Incident
    Enforce --> Incident
```

**Endpoint agent: how it protects a computer**

The agent has two parts. The **agent service** runs with administrator rights and holds the policy, the detection engine and the offline event queue. The clipboard and the screen belong to the signed-in person, so a small **session helper** runs inside each user session and asks the service for a decision. The helper never decides anything itself, which keeps the part running with the employee's own rights as simple as possible.

```mermaid
flowchart TB
    subgraph Device["Employee computer"]
        subgraph UserSession["User session, runs as the signed-in user"]
            Helper["Session helper<br/>clipboard · screen capture"]
        end
        subgraph Service["Agent service, runs with administrator rights"]
            Core["Local detection<br/>and policy engine"]
            Sensors["File · USB · print sensors"]
            Cache[("Encrypted<br/>policy cache")]
            Outbox[("Offline<br/>event queue")]
            Updater["Self-updater<br/>signed releases only"]
        end
        subgraph OSLayer["Operating system"]
            KFile["File protection"]
            KNet["Network protection"]
        end
    end
    Backend["ZeroShield DLP service"]

    Helper <-->|"asks for a decision"| Core
    Sensors --> Core
    KFile <-->|"allow or deny"| Core
    Core -->|"blocked destinations"| KNet
    Core --- Cache
    Core --> Outbox
    Outbox -->|"events, retried until delivered"| Backend
    Backend -->|"rules for this computer and its users"| Core
    Backend -->|"signed updates"| Updater
```

**One event, end to end: a card number copied on a Windows laptop**

```mermaid
sequenceDiagram
    autonumber
    actor Employee
    participant Helper as Session helper
    participant Agent as Agent service
    participant DLP as DLP service
    participant GW as Sign-in gateway
    actor Analyst

    Employee->>Helper: Copies a card number in Excel
    Helper->>Agent: Clipboard text and owning app (excel.exe)
    Agent->>Agent: Card number found, Luhn check passes<br/>rule 'Block card data' matches
    Agent-->>Helper: Verdict is block
    Helper->>Helper: Clears the clipboard<br/>and its clipboard history entry
    Agent->>Agent: Event saved to the offline queue
    Agent->>DLP: Event uploaded, retried while offline
    DLP->>DLP: Event stored and incident opened<br/>sample masked to the last 4 digits
    Analyst->>GW: Opens the incident queue
    GW->>DLP: Request scoped to the analyst's organisation
    DLP-->>GW: That organisation's incidents only
    GW-->>Analyst: Who, which computer, what, which rule, what was done
```

**Security boundaries: one way in**

```mermaid
flowchart LR
    Browser["Your security team<br/>in a web browser"]
    Agents["Endpoint agents"]
    WebProxy["Your web proxy"]
    MTA["Your mail server"]

    subgraph Product["ZeroShield DLP"]
        Entry["Secure entry point<br/>HTTPS only"]
        Console["Web console"]
        Gateway["Sign-in gateway<br/>sign-in · roles · tenant isolation"]
        DLP["DLP service"]
        MailFilter["Mail filter"]
    end

    Browser -->|"HTTPS"| Entry
    Agents -->|"HTTPS"| Entry
    Entry --> Console
    Entry -->|"signed-in requests"| Gateway
    Entry -->|"agent check-in only"| DLP
    Gateway -->|"scoped to your organisation"| DLP
    WebProxy -->|"encrypted ICAP"| DLP
    MTA --> MailFilter
    MailFilter --> DLP
```

* 🚪 The DLP service's management functions are never exposed to the internet. People reach them only by signing in to the console, and the browser never holds a key to the DLP service.
* 🏷️ The browser never chooses which organisation's data it sees. The sign-in gateway takes the organisation from the signed-in session and applies it to every request; a request naming another organisation is refused and recorded in the audit log.
* 🤖 Agents can reach only their own check-in, enrolment and installer-download functions, and each checks its own credential.

---

## Core Modules

Everything is managed from the ZeroShield DLP console. Its **Data Protection** screens:

| Screen | What it is for |
| :--- | :--- |
| **Overview** | Open incidents, agents online, sensitive findings, scans, the 30-day trend and channel activity |
| **Incidents** | Every detection that opened an incident, with filters, triage and history |
| **Policies** | The enforcement mode, computer settings (including Block screen capture) and the rules in force |
| **Endpoints** | The enrolled fleet, channel health, every endpoint event with CSV export, installers and agent updates |
| **Connections** | One card per route data can take, whether it is protected, and how to set it up |
| **Data at Rest** | Repositories, scans, findings, clean-up history and schedules |
| **Data in Motion** | Activity per channel and every email decision |
| **Detection & Tuning** | Your customer lists and documents, the rules in force and what has matched |
| **Reports** | Channel coverage, detector health and compliance reports |

The **Settings** screens are **User Management**, **Groups**, **Access Control**, **Data Retention** and **My Account**, plus **Organisations** for ZeroShield operators. [Groups](#3-groups) and [Data Retention](#10-data-retention--export) are described below, and the rest under [Organisations, Users & Roles](#organisations-users--roles).

**A live console.** The Overview, Incidents, Endpoints, Data at Rest, Data in Motion and Reports screens refresh on their own every 15 seconds while they are open, so new incidents, check-ins, scan results and email decisions appear without reloading. A new incident raises a notice on whichever page you are on, with a link straight to it, and the Incidents link shows how many are open. When ZeroShield releases a new version of the console, an open tab offers a one-click reload. Light and dark themes are built in.

### 1. Detection Engine

Every channel hands content to the same engine. The detectors run together and their results are merged into **one verdict**: a sensitivity tier (Regulated, Confidential, Internal or Public), the categories found, a confidence score and a masked sample.

**Built-in detectors**

| Category | What it finds | How false alarms are kept down | Default tier |
| :--- | :--- | :--- | :--- |
| 💳 **Payment cards** | 13–16 digit card numbers, with or without spaces and dashes | Luhn checksum | Regulated |
| 🆔 **Aadhaar** | 12-digit Aadhaar numbers | Verhoeff checksum | Regulated |
| 🧾 **PAN** | Permanent Account Numbers | Structure rules, including the holder-type letter | Regulated |
| 🏢 **GSTIN** | GST identification numbers | Format and check character | Regulated |
| 🛂 **Indian passport** | Passport numbers | Format, and only near the word "passport" | Regulated |
| 🔑 **Secrets and API keys** | AWS access keys, PEM and PGP private keys, GitHub, Slack, Google, Stripe, OpenAI and Anthropic keys, JSON Web Tokens | Each issuer's fixed prefix and format | Regulated |
| 📱 **Indian mobile numbers** | 10-digit numbers starting 6–9, with an optional +91 or 0 | Format and word boundaries | Internal |
| 🏦 **IFSC codes** | Bank branch codes | Format | Internal |
| 💸 **UPI IDs** | IDs on known payment-app and bank handles | Known handles only, so ordinary email addresses do not match | Internal |
| 📧 **Email addresses** | Any email address | Format | Internal |
| 🏷️ **Confidentiality markings** | CONFIDENTIAL, RESTRICTED, TOP SECRET, SALARY, FINANCIAL REPORT and similar | Keyword list | Internal |

Regulated categories block by default and Internal categories warn by default. Your policies decide the final action for every category on every channel. Context words such as *card*, *account*, *PAN* or *Aadhaar* near a match raise its confidence.

**Your own data**

* 🧬 **Exact Data Match (EDM)**: upload a customer or employee list as CSV or TSV. ZeroShield stores salted, keyed hashes of the values, never the values, and then catches *those exact* records (this customer's PAN, that account number) rather than anything shaped like one. Rotating the salt does not break existing lists.
* 📑 **Indexed Document Match (IDM)**: upload contracts, designs, price lists or board papers as text, Word, PDF or Excel files. ZeroShield fingerprints them, and an excerpt of about 35 words or more found elsewhere counts as a match, even when only part of the document was copied.
* 🧩 **Custom detectors**: add your own patterns, for example an employee ID such as EMP-123456, optionally narrowed by nearby words, and test them against sample text in the console before saving.
* 🔤 **Keywords**: project code names and internal markings, for example "Project Phoenix".

Customer lists and indexed documents are matched in email, cloud apps, network uploads and stored data. On laptops, the agent applies the built-in detectors, custom detectors and keywords locally.

**Beyond plain text**

* 📄 Text is extracted from PDF and Office documents, spreadsheets and archives (zip, tar and gzip, nested up to two levels deep) before it is checked.
* 🖼️ **OCR** reads text in images and screenshots. On Windows computers the agent uses the OCR engine built into Windows, so there is nothing extra to install.
* 🤖 An optional **ML classifier** recognises document types that have no fixed pattern, such as NDAs, invoices and résumés.

> 📸 **[Screenshot: dlp-detection-tuning.png]** Detection & Tuning: customer lists and documents, the rules in force, and what has matched by tier, channel and action.

### 2. Policies & Enforcement

A policy is the organisation's rulebook: what to look for, where, for whom, and what to do when it is found.

**Enforcement mode** is one switch over every rule:

| Mode | What happens | When to use it |
| :--- | :--- | :--- |
| 👀 **Monitor** | Everything is recorded and nothing is stopped | The first week, to see what really happens without disturbing anyone |
| ⚠️ **Warn** | People are warned and allowed to continue; the event is recorded | To build awareness before enforcing |
| ⛔ **Block** | Rules are enforced exactly as written | Full enforcement |

**What a rule contains**

| Field | Meaning |
| :--- | :--- |
| **Name** | For example "Block Aadhaar numbers" |
| **Categories** | Built-in categories, your customer lists (EDM) and your documents (IDM) |
| **Channels** | Where the rule applies: laptops, email, cloud apps, network or stored data |
| **Applies to** | **Everyone**, **only these groups** or **everyone except these groups** (see [Groups](#3-groups)) |
| **Minimum confidence** | How sure the engine must be before acting; checksum-valid numbers score high |
| **Priority** | When several rules match, the most severe action wins, and priority decides between rules with the same action |
| **Blocked destinations** | Sites or addresses laptops cannot connect to, for example wetransfer.com |
| **Keywords and custom patterns** | Your own markers and formats, with a live test box |
| **Open an incident** | Record matches for the security team |
| **Notify the user** | Show a Windows notification when a copy is warned about, blocked or masked |
| **Let the user continue with a reason** | On Windows, a blocked file save, USB copy or clipboard copy asks the person why. With a reason, the file or copy is restored and the reason appears on the incident for review, with any card number or PAN typed into it masked |

**Actions**

| Action | What it does |
| :--- | :--- |
| ✅ **Allow** | Let it through, for example for a team permitted to handle this data |
| ⚠️ **Warn** | Let it through, tell the person and record it |
| ⛔ **Block** | Stop it. On a laptop the clipboard is cleared, a file or USB copy is moved to quarantine, the print job is cancelled and the connection is refused |
| ✂️ **Redact** | Mask the sensitive part and let the rest through: in email, and in text copied on Windows |
| 🔐 **Encrypt** | Encrypt the sensitive parts of an email, or a stored file in place |
| 📦 **Quarantine / Move** | Move an email or a stored file into quarantine |
| 📝 **Tombstone** | Quarantine a stored file and leave a note in its place saying where it went |
| 🚫 **Revoke** | Remove public or shared access to a stored file so only the owner keeps it |

**Computer settings** decide what laptops watch: which channels are on, up to eight folders to watch (for example Documents, Desktop and Downloads), and how often the screen is sampled (from every 30 seconds to every hour). They also decide whether USB storage is open to every drive or only to **approved drives**, identified by serial number, on Windows and Linux. A copy onto a drive that is not approved opens an incident with an **Approve this drive** button. One more switch, **Block screen capture**, stops screenshots and screen recordings across the organisation (see [Block Screen Capture](#block-screen-capture)). Laptops pick up a change within about a minute.

> 📸 **[Screenshot: dlp-policies.png]** Policies: enforcement mode, computer settings (including Block screen capture) and the saved rules.
>
> 📸 **[Screenshot: dlp-rule-editor.png]** Rule editor: categories, channels, who the rule applies to, confidence, blocked destinations and a live custom-detector test.

### 3. Groups

Not every rule fits everyone. **Groups** collect computers and people, such as *Finance*, *Contractors* or *Branch Operations*, so a rule can be aimed at exactly the teams it is meant for.

* 👥 **Computers and people together**: pick enrolled computers from a list, and add people by the name they sign in to their computer with (for example *asha* or *CORP\asha*) or by their email address. A person is matched on any computer they use.
* 🎯 **Applies to**: every rule can apply to **Everyone**, to **Only these groups** or to **Everyone except these groups**.
* 🌐 **Across channels**: each computer receives only the rules that apply to it and to the people who use it. In email, cloud apps and web uploads, a rule follows the person the content belongs to, such as the sender or the file's owner.
* 🔎 **Clear at a glance**: each group shows its computers, its people and the rules that use it. A group cannot be deleted while a rule still uses it.
* ⚡ **Quick to take effect**: computers pick up a change to a group within about a minute.

**Example:** block card numbers on USB drives for *Everyone except Treasury*, and give Treasury its own rule that only warns.

> 📸 **[Screenshot: dlp-groups.png]** Groups: each group's computers, people and the rules that use it.

### 4. Endpoint DLP

The ZeroShield agent is a lightweight program that runs on each employee's computer. It downloads the organisation's policy, checks activity against it **on the device**, enforces what the policy says and reports back. Because decisions are made locally, protection continues while a laptop is offline.

| Channel | What the agent does | Example |
| :--- | :--- | :--- |
| 📁 **Files** | Checks files created, written, copied or renamed in watched folders, and blocks or quarantines sensitive ones | A spreadsheet of card numbers saved to Documents is blocked |
| 📋 **Clipboard** | Checks each copy and the app that made it, including copied pictures, which are read with OCR on Windows. A blocked copy is cleared or, on Windows, masked, and is also removed from Windows clipboard history (Win+V) | An Aadhaar number copied from a customer record is cleared from the clipboard |
| 💾 **Removable media** | Checks files written to USB drives and quarantines blocked files on the drive; optional approved-drives-only device control | A payroll export copied to a personal stick is quarantined on the stick |
| 🖨️ **Print** | Reads the content of each print job and cancels the job at the spooler when blocked | Printing a customer list with PAN numbers is cancelled |
| 🖥️ **Screen capture** | Samples the screen, reads it with on-device OCR and records any sensitive data shown. [Block Screen Capture](#block-screen-capture) stops screenshots and screen recordings altogether | Card numbers left open on screen are recorded with a masked sample |
| 🌐 **Network** | Refuses connections to blocked destinations, whichever browser or tool is used | Uploads to wetransfer.com fail in every browser |

The Endpoints screen also lists every event the computers report, including warnings and recorded matches that opened no incident, and exports them to CSV.

> 🎬 **[Video: dlp-endpoint-demo.mp4]** Clipboard, file, USB and network blocks on a laptop, each appearing in the incident queue.
>
> 📸 **[Screenshot: dlp-endpoints.png]** Endpoints: every enrolled computer with its user, operating system, agent version, last check-in and a health dot per protection channel.

Supported operating systems and installers are listed under [Supported Systems](#supported-systems).

#### Block Screen Capture

One switch in **Policies → Computer settings** stops screenshots and screen recordings on every computer in the organisation:

* ⌨️ **Capture keys switched off on Windows**: PrintScreen, in every combination, and the Snipping Tool shortcuts do nothing.
* 🛑 **Capture apps closed as they start**, on Windows, macOS and Linux: the built-in tools (Snipping Tool, Xbox Game Bar, the macOS Screenshot app, GNOME Screenshot, Spectacle) and popular apps such as OBS, Loom, ShareX, Snagit, Greenshot, Lightshot, Bandicam and CleanShot.
* 🗑️ **Saved captures removed**: a screenshot or screen recording saved anyway is deleted as soon as it appears in the screenshots or recordings folder.
* 📞 **Calls keep working**: Teams, Zoom and Meet calls are not affected.
* 🔔 **Attempts on record**: attempts are recorded as incidents that say what was stopped, for example *SnippingTool.exe closed*. On Windows, the person also sees a notice that screen capture is turned off.
* 👀 **Try it first**: in Monitor mode, capture apps are recorded and nothing is closed or removed.

### 5. Data in Motion

Data being sent is checked against the same policies on whichever route it takes.

**📧 Email**

| Route | How it connects | What it can do |
| :--- | :--- | :--- |
| **Before it leaves** | Your mail server (for example Postfix) passes each outgoing message to the ZeroShield mail filter | Deliver, deliver with a warning header, redact or encrypt the sensitive parts, or reject or hold the message |
| **Gmail and Outlook** | The Google Workspace or Microsoft 365 connection | Checks every sent message within minutes, including mail sent from phones, and opens an incident for any that breaks the policy |

Attachments are opened and checked, including archives. A zip or PDF attachment that would still carry card numbers after redaction is rejected rather than delivered. The Data in Motion screen lists every message ZeroShield ruled on, not only the blocked ones, and shows a recipient count rather than recipient addresses.

**☁️ Cloud apps**

* **Google Drive** (through Google Workspace) and **OneDrive** (through Microsoft 365) are connected by your administrator approving ZeroShield in your own admin console. No password is shared, and withdrawing the approval cuts access immediately.
* Every few minutes ZeroShield reads file activity (uploads, new files, edits and sharing changes) and checks each file touched with the same detectors, customer lists and policies.
* When the policy blocks and the file is shared outside the organisation (a public link, another domain or an outside person), **that outside sharing is removed**. The owner keeps the file and nothing is deleted.
* Events from an existing cloud access security broker (CASB) can also be forwarded. Sanctioned apps get content checks; uploads to unsanctioned apps are blocked even when the file is clean.

**🌐 Company network**

* Your web proxy (Squid, Zscaler, Palo Alto, Fortinet and others) asks ZeroShield over **ICAP** before letting an upload leave. A blocked upload shows the person a ZeroShield page instead.
* Each organisation gets its own encrypted ICAP address, with the certificate downloadable from the console.
* An HTTPS inspection policy lists which hosts must be inspected and which must bypass interception (for example apps that pin their certificates). Your proxy performs the interception, and an in-scope HTTPS connection that was not inspected is refused rather than waved through.
* FTP and SFTP uploads passed on by a file-transfer gateway are allowed or refused in the same way.

> 🎬 **[Video: dlp-email-cloud-demo.mp4]** A Gmail message carrying a PAN is recorded with a masked sample, and a Google Drive file with Aadhaar numbers loses its public link within minutes.
>
> 📸 **[Screenshot: dlp-data-in-motion.png]** Data in Motion: activity per channel and every email decision with its outcome.

### 6. Data at Rest

Sensitive data sitting in storage is often the largest hidden risk. ZeroShield finds it, shows exactly where it is and cleans it up, reversibly.

| Repository | Examples | How ZeroShield gets access |
| :--- | :--- | :--- |
| ☁️ **Amazon S3** | Buckets and prefixes | A **read-only IAM role in your own AWS account**, trusted only with an external ID unique to your organisation. No keys are shared, and the console shows the exact policies to create |
| ☁️ **Azure Blob Storage and ADLS Gen2** | Containers and prefixes | An account key or SAS token, stored encrypted |
| ☁️ **Google Cloud Storage** | Buckets and prefixes | A service-account key, stored encrypted |
| 🗃️ **Databases** | PostgreSQL, MySQL, SQL Server, Oracle | A database login, stored encrypted. Columns are **sampled** and no rows are stored |
| 🗂️ **Windows file shares** | SMB shares | A share login, stored encrypted |

Databases and file shares are scanned over the network, with nothing to install on them.

**How it works**

```mermaid
flowchart LR
    Add["Add a repository<br/>S3 · Azure · GCS<br/>database · file share"] --> Scan["Scan now or on a schedule<br/>full or incremental"]
    Scan --> Find["Findings<br/>which file, object or column<br/>holds what"]
    Find --> Clean{"Clean up"}
    Clean --> Q["Quarantine or move"]
    Clean --> T["Tombstone"]
    Clean --> R["Revoke access"]
    Clean --> E["Encrypt in place"]
    Q & T & R & E --> Undo["Undo with one click"]
```

1. **Add a repository** from the console.
2. **Scan** now or on a schedule, in full or incrementally. Repeat scans skip anything that has not changed, and scanning can be rate-limited to protect production systems.
3. **Review findings**: which file, object or column holds what (for example *customers.csv: card numbers and PAN*), each with a masked sample.
4. **Clean up** with one click, or turn on *clean up automatically after each scan*.

| Clean-up | Effect | Undo |
| :--- | :--- | :--- |
| 📦 **Quarantine / Move** | The file moves into a locked quarantine location | Moves it back |
| 📝 **Tombstone** | Quarantine, plus a short note in its place saying why it is gone | Puts the file back |
| 🚫 **Revoke** | Public and shared access is removed; only the owner keeps it | Restores the previous access |
| 🔐 **Encrypt** | The content is replaced by its encrypted form (AES-256) | Decrypts it in place |

Findings in Amazon S3 are cleaned up in one click, and every clean-up can be undone. The console gives you the extra clean-up permission to add to the same AWS role.

> 🎬 **[Video: dlp-data-at-rest-demo.mp4]** An S3 bucket is scanned, a file with card numbers is quarantined, and the quarantine is undone.
>
> 📸 **[Screenshot: dlp-data-at-rest.png]** Data at Rest: repositories, scans, findings with masked samples, and the clean-up history with Undo.

### 7. Incident Management & Investigation

Every block or warning, and every match a rule asks to record, becomes an incident that answers an investigator's first questions:

* 👤 **Who**: the user or email sender, with a stable pseudonymous reference for linking incidents across channels.
* 💻 **Where**: the computer, the Drive or OneDrive file, or the storage location.
* 🔎 **What**: the tier, the categories and a **masked sample**: `**** **** **** 1111` for a card, `ABCPS****F` for a PAN, `**** **** 9012` for an Aadhaar number. The real value is never stored.
* 📜 **Which rule** matched and **what was done**.
* 🧭 **Channel and source**: *what the data did* (clipboard, USB, print, screen, file, network, email, web or at rest) and *what observed it* (the endpoint agent, the mail filter, your web proxy, a cloud-app connection or the storage scanner).

**Workflow**: Open → Investigating or Escalated → Resolved, with optional notes and a timeline of who changed what.

**Live**: new incidents appear as they happen. A notice with a link appears on any page of the console, and the queue refreshes every 15 seconds. Blocks are filed as High severity and warnings as Medium, and the queue filters by status, severity, channel, source and sensitivity tier.

**Reasons to review**: when someone continued past a block with a reason, the incident shows the reason and the queue marks it, so an analyst can decide whether it holds.

**Less noise**: repeated events are grouped. Fifty blocked connections from one computer to one site within an hour become one incident with an attempt count.

> 📸 **[Screenshot: dlp-incident-detail.png]** Incident detail: the detection, masked evidence, workflow and timeline.

### 8. Connections

The Connections screen answers "what is protected?" with one card per route. Each card shows its state (**Connected**, **Available** or **Off**) and the setup steps:

| Route | What it covers | Setup |
| :--- | :--- | :--- |
| 💻 **Laptops and desktops** | Copy and paste, USB drives, printing, files, screenshots and network uploads | Download the installer from Endpoints and run it on each computer |
| 🗄️ **Stored data** | Cloud buckets, file shares and databases, on demand or on a schedule | Add a repository; for Amazon S3, create the read-only role the form describes |
| 📧 **Email** | Outgoing email before it leaves, or every sent message soon after | Route outgoing mail through the ZeroShield mail filter, or connect Google Workspace or Microsoft 365 |
| ☁️ **Cloud apps** | Files uploaded to and shared from Google Drive or OneDrive | Your administrator approves ZeroShield; no password is shared |
| 🌐 **Company network** | Uploads leaving through your web proxy | Add ZeroShield as an ICAP service in your web proxy |

> 📸 **[Screenshot: dlp-connections.png]** Connections: one card per route, with its live state and setup steps.

### 9. Dashboards, Reports & Compliance

**Overview** is the security team's home page: open incidents, agents online (and how many report tampering), sensitive findings, scans, the 30-day incident trend with its blocked share, and activity per channel. It refreshes on its own every 15 seconds.

**Reports** is written for management and auditors:

* 📈 **Channel coverage**: for each channel, how many events it checked, how many it blocked, and its health, downloadable for your records.
* 🩺 **Detector health**: how many detectors are loaded, enabled and actually able to match. A detector that is switched on but cannot match (for example a customer-list matcher with no list loaded) is named, with the reason.
* 📚 **Compliance reports** for the **DPDP Act 2023**, **PCI DSS v4.0**, **GDPR** and the **HIPAA Security Rule**. Each shows the data the law protects, how far your policy covers it (including categories with no rule, or only a recording rule), the incidents, and the **data that got through**, which helps decide whether a breach must be reported (for example under GDPR's 72-hour rule). Reports contain no sample of the data, masked or not, and can be printed to PDF.

**Blank is not zero.** A blank means the feature is switched off, so nothing was measured; a zero means it was measured and nothing was found. A dashboard showing a confident zero for a channel nobody enabled would mislead the people relying on it.

> 📸 **[Screenshot: dlp-reports.png]** Reports: channel coverage, detector health and a DPDP Act 2023 compliance report.

### 10. Data Retention & Export

Decide how long the activity your computers report is kept, and take a copy whenever you need one, under **Settings → Data Retention**.

* 🗓️ **Your retention period**: keep endpoint events for 30, 90 or 180 days, 1 or 2 years, or forever. The default is 90 days.
* 🧹 **Automatic clean-up**: events older than the period are deleted automatically, within a few hours.
* 🛡️ **Evidence always kept**: incidents, and the events that opened them, are kept whatever period you choose.
* ✋ **Confirm before deleting**: shortening the period asks you to confirm first, and offers to export everything before anything is removed.
* 📊 **At a glance**: how many events are stored, the date of the oldest, and the period in force.
* 📥 **Export to CSV**: download endpoint events as a CSV file that opens in Excel or Google Sheets, filtered by date, channel and verdict. Each row says what happened, on which computer, by whom, when and which rule matched, with no file contents. The Endpoints screen exports what it is showing, including one computer's events, in the same way.
* 🔑 **Who can do what**: administrators set the period; security analysts and auditors can see it and export events.

> 📸 **[Screenshot: dlp-data-retention.png]** Data Retention: events stored, the retention period in force and the CSV export.

---

## Endpoint Agent & Deployment

### Supported Systems

| | **Windows** | **Linux** | **macOS** |
| :--- | :--- | :--- | :--- |
| **Versions** | Windows 11 and Windows Server 2022, 64-bit | Debian 12+, Ubuntu 22.04+, RHEL, Rocky and AlmaLinux 9+, Amazon Linux 2023, 64-bit | macOS 14 Sonoma or later |
| **Installer** | MSI | .deb and .rpm | .pkg |

On Linux desktops, both X11 and Wayland sessions are supported.

### Installation & Enrolment

* 📥 **One-file installers from the console**: Endpoints → *Add computers* → choose the operating system → *Download installer*. On Windows it is a double-click and an administrator prompt; on Linux and macOS it is one command in a terminal. The installer downloads the agent, installs it, enrols the computer and reports whether that worked.
* 🧰 **Fleet deployment**: a silent-install command is provided for software-distribution tools.
* 🎟️ **Enrolment tokens** are time-limited and can do exactly one thing: add computers to your organisation. They cannot read incidents or change policy.
* 🔑 **Per-device identity**: each computer receives its own credential when it enrols. Revoking an enrolment token stops new enrolments without disconnecting enrolled computers, and **retiring** a device stops its credential working while keeping its history.
* ▶️ **Starts protecting on its own**: the service starts at boot, waits until it is enrolled, then fetches its policy and begins enforcing.

### Automatic, Signed Updates

```mermaid
flowchart LR
    Sign["ZeroShield publishes<br/>a signed release"] --> Roll["Console: Agent updates<br/>pilot devices or everyone"]
    Roll --> Fetch["Agents check in,<br/>download it and<br/>verify the signature"]
    Fetch --> Install["Installs itself"]
    Install --> Up{"New version<br/>starts?"}
    Up -->|"yes"| Run["Runs the new version<br/>restarts stopped protection"]
    Up -->|"no"| Back["Previous version<br/>puts itself back"]
```

* ✍️ Every release is digitally signed by ZeroShield, and the agent installs only a release whose signature matches a key built into the agent. A compromised server could hold an update back, but could not make an agent install anything ZeroShield did not sign.
* 🎯 Roll out to **pilot devices** first, then to **every device** on that operating system, or pause updates. Agents check in about once a minute.
* ↩️ Only upgrades are offered. If a new version fails to start, the previous version puts itself back. A bad release is revoked and replaced by a newer one, never by pushing an older version across the fleet.

### Self-Protection & Resilience

* 🛡️ **Tamper resistance**: a standard user cannot read or overwrite the agent's identity or policy, stop, disable or kill the service, or replace its program files.
* 🚩 **Tampering is visible**: if anyone stops part of the agent, it records a tamper flag, and the next check-in carries it to the console.
* 🩹 **Self-healing**: any part of the agent that stops is restarted automatically, the session helper is relaunched in every signed-in session, and protection starts again after a reboot.
* 📴 **Offline**: the agent keeps enforcing its encrypted, cached policy and queues events on disk, then uploads them when the network returns.
* 🧯 **Safe by design**: protection never stops a computer from working, and the Endpoints screen shows the health of each protection on every computer.

---

## Organisations, Users & Roles

* 🏢 **Sign-up and approval**: an organisation signs up from the ZeroShield DLP sign-in page with its company name and its administrator's name, work email and password. ZeroShield operators approve or reject each request on the **Organisations** screen. Once a request is approved, the organisation is created and the person who signed up becomes its first administrator.
* 🔐 **Fully private**: each organisation has its own users, agents, rules, incidents and data, and never sees another organisation's.
* ⏸️ **Suspend and resume**: an operator can suspend an organisation, which signs its people out at once and stops them signing in until it is resumed. Nothing is deleted.
* 👤 **User Management**: administrators add people with a role, change roles, reset passwords (which ends that person's sessions) and disable or re-enable accounts. If the administrator leaves the password blank, one is generated and shown once, because only its hash is kept. The **Auth Activity** tab lists sign-ins and account changes.
* 🗝️ **Access Control** shows exactly what each role may do and how many people hold it. The permissions are read from the rules the server enforces, so the page cannot drift from what is actually allowed.
* 🙋 **My Account** shows each person their name, role and organisation. Everyone can change their own password from the menu under their name.

**Roles** change what the console shows and, more importantly, what the server permits:

| Role | What they can do |
| :--- | :--- |
| **Administrator** | Everything, including policies, groups, data retention, adding computers and managing users |
| **Security Analyst** | Triage incidents, run scans, test content against the detectors, clean up findings and export endpoint events. Can see the user list, groups and retention, but cannot change policies, groups or retention, add computers or manage users |
| **Auditor** | Read every screen, including the user list, and export endpoint events; change nothing |
| **Employee** | Sign in and see their own account; no console access |

> 📸 **[Screenshot: dlp-user-management.png]** User Management: people and their roles, and the Auth Activity log.

---

## Security & Data Protection

### Privacy by design
* 🎭 **Masked at capture**: incidents and findings keep a masked sample and the category, never the matched value.
* 🧬 **Fingerprints, not copies**: customer lists are stored as salted, keyed hashes and documents as fingerprints.
* 🗃️ **Sampling, not copying**: database scans sample columns and store no rows; storage scans keep findings, not file contents.
* ✉️ **Minimal email data**: the email view shows a recipient count, not recipient addresses.
* 🗓️ **Retention you control**: endpoint events are deleted automatically after the period you choose; incidents, and the events that opened them, are kept.
* 📄 **Safe exports**: CSV exports carry no file contents, and no cell in them can run as a spreadsheet formula.
* 🕶️ **Optional pseudonymous mode**: incidents keep only a keyed hash of the user and no name or computer name, for organisations whose rules (a works council, for example) require investigators to see a pseudonym first.

### Access control & tenant isolation
* 🏢 Each organisation is a separate tenant, enforced by the server: the tenant comes from the signed-in session, and a request naming another tenant is refused and recorded in the audit log.
* 👥 **Role-based access**, checked by the server on every request. Anything a role is not explicitly allowed to do is refused.
* 🔐 **Sign-in security**: passwords of at least 12 characters, stored only as a strong one-way hash (Argon2id); sessions that end after 30 minutes idle or 12 hours in total; protection against cross-site request forgery; and a 15-minute lockout after 5 failed sign-ins. Changing a password ends the account's other sessions.
* 📝 **Audit trail**: sign-ins (including failed and locked-out attempts), password changes and resets, changes to users, organisation approvals and suspensions, and refused cross-organisation requests are recorded in the audit log. Administrators, security analysts and auditors see their own organisation's entries under User Management → Auth Activity. Policy changes and every incident status change are recorded too.

### Credentials
* ☁️ **AWS**: a read-only role in your own AWS account, usable only on behalf of your organisation. No AWS keys are stored.
* 🔗 **Google Workspace and Microsoft 365**: approved by your administrator in your own admin console and revocable at any time. A Microsoft 365 approval is bound to the ZeroShield organisation that requested it, so one organisation cannot connect another company's directory.
* 🧷 **Other storage** (Azure, Google Cloud Storage, databases, file shares): credentials are encrypted at rest and never shown again. A storage address with a password typed into it is refused, so a secret is never saved by mistake.

### Endpoint security
* ✍️ Signed updates, checked against a key built into the agent.
* 🔒 The policy kept on each computer is encrypted (AES-256) and readable only by administrators.
* 🎟️ The session helper has its own short-lived credential, withdrawn at sign-out, and cannot read the agent's secrets.
* 🌐 Agents connect only over HTTPS, to a server with a publicly trusted certificate.

---

## Measured Performance

Measured results, not estimates.

| What was measured | Result | Conditions |
| :--- | :--- | :--- |
| File protection: time added to a file save | **1.2 ms** typical, within **2.4 ms** for 95% of saves | Windows Server 2022, with Microsoft Defender running |
| Stability under load | 47-minute stress test: about **1.2 million** file operations checked, **none missed**, **no system crashes** | Windows Server 2022; agent memory use stayed between 22 and 24 MB |
| Network protection: time added to a connection | **1 ms** typical, within **2 ms** for 95% of connections | Windows Server 2022 |
| On-device OCR | A PAN card image read correctly in **61 ms** | Windows 11, using the OCR built into Windows |
| Offline laptop | 6 events held while the server was unreachable, **all 6 delivered within 10 seconds** of reconnecting | Windows Server 2022 |
| Server response time | **95%** of checks answered within about **30 ms**, against a 200 ms target | Cloud environment, 500+ checks |

---

## Governance & Compliance

| Framework | How ZeroShield DLP supports it |
| :--- | :--- |
| 📜 **DPDP Act 2023 (India)** | Detects Aadhaar, PAN, passport, mobile, email, UPI, IFSC and card data, controls how it leaves, and has a dedicated compliance report |
| 🏦 **RBI guidelines** | Data leak prevention for customer and account data on every channel, with an auditable incident trail |
| 💳 **PCI DSS v4.0** | Luhn-validated card detection on every channel, discovery of stored card data, and a dedicated compliance report |
| 🔏 **GDPR** | Personal-data detection, a list of data that got through to support the 72-hour breach decision, and a dedicated compliance report |
| 🏥 **HIPAA Security Rule** | Detects the identifiers that make health information PHI, supports custom detectors for medical record numbers, and has a dedicated compliance report |
| 📋 **ISO 27001:2022 and SOC 2** | Applies data leakage prevention (ISO 27001:2022 control 8.12) on every channel and controls how sensitive data is moved and shared. The incident history, coverage report and audit log give auditors the evidence |

ZeroShield DLP also supports governance by:

* Enforcing policy where data leaves: the laptop, the mail server, the proxy, the cloud app or the storage location.
* Keeping an auditable trail of every decision, with masked evidence and the rule that applied.
* Keeping endpoint activity only as long as your policy says, with automatic deletion and CSV export, which helps meet the storage-limitation and erasure duties in GDPR and the DPDP Act.
* Showing coverage gaps openly, so auditors see what is and is not protected.

---

## Recommended Rollout

```mermaid
flowchart LR
    C["Connect<br/>routes and a pilot group"] --> M["Monitor<br/>record, stop nothing"] --> T["Tune<br/>lists, detectors, thresholds"] --> W["Warn<br/>tell people, let them continue"] --> B["Block<br/>enforce as written"] --> P["Prove<br/>reports for auditors"]
```

1. **Connect** the routes that matter on the Connections screen, install agents on a pilot set of computers, and put them in a *Pilot* group.
2. **Monitor** for a week. Nothing is stopped and no incidents are opened; endpoint events, email decisions and scan findings show what would have been caught.
3. **Tune**: add customer lists, documents, custom detectors and exceptions, adjust confidence thresholds, and use Groups to give each team the rules it needs.
4. **Warn** to build awareness, then **Block**. Start new rules on the *Pilot* group and widen them to everyone, and roll agent updates out to pilot devices first.
5. **Prove**: give auditors the compliance report, the channel coverage report and, where needed, an export of endpoint events.

---

## Target Users & Example Scenarios

ZeroShield DLP is built for organisations that hold regulated personal or financial data, or intellectual property they cannot afford to lose. The scenarios below are illustrative.

### Banking & Financial Services
Protect customer, account and card data across branches, back offices and cloud storage, in line with the DPDP Act and RBI expectations.

**Example scenario:** Ananya is the CISO of a private bank. She installs the agent on branch and back-office computers in Monitor mode and uploads the customer master (account numbers and PANs) as an Exact Data Match list, so ZeroShield recognises the bank's real customers rather than anything shaped like a PAN. After a week of tuning she moves to Block: card numbers copied to the clipboard are cleared, print jobs carrying card numbers or PANs are cancelled, and exports copied to USB drives are quarantined. The USB rule applies to everyone except the Treasury group, whose own rule only warns, so settlement files still move. A scan of the bank's S3 buckets finds old customer exports, which are quarantined with one click. For the audit committee she exports the DPDP compliance report, which lists what got through as well as what was stopped.

### Fintech & Payments
Keep card data inside the cardholder data environment, and keep secrets out of chat, email and uploads.

**Example scenario:** Rohan leads security at a payments company in PCI DSS scope. ZeroShield samples the production databases, without copying any rows, and finds card numbers in a support-ticket table that should never have held them. On developer laptops, copied AWS keys, Stripe live keys and private keys are cleared from the clipboard, and the company's web proxy refuses uploads of card data to paste sites. The PCI DSS v4.0 report shows which card-data rules block, which only record, and every incident in the period.

### Contact Centres & BPO
Protect the customer data agents see on screen all day, across large teams and shifts.

**Example scenario:** Meera runs security for a contact centre that handles card and Aadhaar details for banking clients. She turns on **Block screen capture**, so agents cannot take screenshots or record customer screens, while Teams and Zoom calls carry on as normal. A rule that blocks card numbers on the clipboard and USB drives applies to everyone except the Team Leads group, whose own rule only warns, so escalations are not held up. Her clients' contracts ask for a year of activity records, so she sets Data Retention to one year and exports a CSV each quarter for the client audit.

### Healthcare
Protect patient identifiers and clinical documents shared by email and cloud drives.

**Example scenario:** Kavita runs IT security for a hospital group. Aadhaar, phone numbers and email addresses are covered out of the box; a custom detector recognises the group's medical record number format, and the patient register is loaded as an Exact Data Match list. When a staff member shares a discharge summary on Google Drive with a public link, the outside sharing is removed within minutes and the incident shows the file and its owner. Investigators see only masked samples, and pseudonymous mode shows them a stable pseudonym instead of the employee's name.

### IT Services & SaaS
Protect client contracts, design documents and credentials across a distributed workforce.

**Example scenario:** Arjun heads security at a software services company that holds client contracts, architecture documents and cloud credentials. He indexes the contracts and design documents with Indexed Document Match, so an excerpt of 35 words or more in an outgoing email or web upload is caught. API keys, tokens and private keys are detected on laptops and in outgoing mail, and the company's web proxy blocks uploads that carry client data. For the ISO 27001 and SOC 2 audits, the incident history and the channel coverage report show auditors where client data is checked and what was blocked.

### Manufacturing & Engineering
Protect drawings, price lists and supplier data that make up the company's competitive edge.

**Example scenario:** Sanjay is IT head at an engineering manufacturer. He indexes design documents and supplier price lists with Indexed Document Match, and adds project code names as keywords. USB storage is limited to company-approved drives by serial number, so a file copied to a personal stick is quarantined on the stick whatever it contains. The company's Amazon S3 buckets are scanned weekly, and stray copies of price lists are tombstoned, leaving a note that tells colleagues where the file went.

---

## Use Cases

* 📜 **DPDP readiness**: find where the personal data of people in India lives, control how it leaves, and report on it.
* 💳 **PCI DSS scope control**: find stored card numbers outside the cardholder data environment and stop card data leaving through any channel.
* 🚪 **Insider risk and departing employees**: watch USB drives, printing, the clipboard, uploads and email for exports of customer data.
* 🖼️ **Screen capture control**: stop screenshots and screen recordings where screens show customer, patient or payment data.
* 🎯 **Contractors and third parties**: give contractors, vendors and temporary staff stricter rules, using Groups.
* ☁️ **Cloud sharing hygiene**: remove public and external links on Drive and OneDrive files that hold sensitive data.
* 🔑 **Secret leakage**: catch API keys, tokens and private keys before they leave laptops, mail and uploads.
* 🗄️ **Data discovery and minimisation**: inventory sensitive data across S3, Azure, Google Cloud, databases and file shares, and quarantine or encrypt exposed files in S3.
* 🚫 **Shadow IT**: block uploads to unsanctioned cloud apps and file-sharing sites.
* 🗓️ **Records retention**: keep endpoint activity for as long as your policy says, and export it for your own archive.
* 🧾 **Audit preparation**: give auditors per-law compliance reports, the channel coverage report and the incident history.

---

## Frequently Asked Questions

**Do we need any other ZeroShield product?**

No. ZeroShield DLP is a standalone product with its own console, sign-up, users and roles.

**Do you store the sensitive data you find?**

No. Matches are masked at the moment of capture, so an analyst sees `**** **** **** 1111` and the category, never the number. Customer lists are kept as salted hashes and documents as fingerprints, and database scans sample columns without storing rows.

**Does it block, or only watch?**

It blocks. Depending on the channel, ZeroShield refuses the file save or the connection, quarantines the USB copy, cancels the print job, holds, rejects, redacts or encrypts the email, removes outside sharing from the Drive or OneDrive file, and clears or masks a sensitive clipboard copy. Sensitive data shown on screen is recorded, and with Block screen capture on, screenshots and screen recordings are stopped. Monitor and Warn modes let you choose when blocking starts.

**Can it stop screenshots and screen recordings?**

Yes. Turn on **Block screen capture** in Computer settings. On Windows the PrintScreen key and Snipping Tool shortcuts stop working; on Windows, macOS and Linux, screenshot and recording apps are closed and any screenshot saved anyway is removed. Teams, Zoom and Meet calls are not affected.

**Can different teams have different rules?**

Yes. Put people and computers into **Groups**, then choose who each rule applies to: everyone, only those groups, or everyone except them.

**What happens when a laptop is offline?**

The agent keeps enforcing its cached policy and queues events on disk. They upload when the network returns.

**Can an employee switch the agent off?**

A standard user cannot stop, disable or kill it, read its configuration or replace its program files. If any part of it is stopped, the agent restarts it, records a tamper flag and reports it to the console at the next check-in.

**Will it disrupt people on day one?**

Not if you start in Monitor mode, which records everything and stops nothing. Move to Warn and then Block once the rules are tuned.

**Is our data separated from other customers?**

Yes, by the server. The browser never chooses an organisation; the sign-in gateway takes it from the signed-in session, and a request naming another organisation is refused and recorded in the audit log.

**How long is our activity data kept, and can we take a copy?**

Endpoint events are kept for the period you choose under **Data Retention**: 30, 90 or 180 days, 1 or 2 years, or forever, with 90 days as the default. Incidents, and the events that opened them, are always kept. You can export endpoint events to CSV at any time.

**Do you need our passwords to scan cloud storage or read cloud apps?**

Not for Amazon S3, which uses a read-only role in your own AWS account, or for Google Workspace and Microsoft 365, which your administrator approves and can withdraw at any time. Credentials for other storage are encrypted at rest and never shown again.

**Can it find data that has no fixed format, such as names or medical record numbers?**

Yes. Add a custom detector for a format your organisation uses, such as its medical record numbers, or upload the values themselves, such as customer names, as a list (Exact Data Match).

**Why does the dashboard sometimes show a blank instead of a zero?**

A blank means that feature is switched off, so nothing was measured. A zero means it was measured and nothing was found.

---

## Complete Product Video

> 🎬 **[Video: dlp-product-walkthrough.mp4]** Full walkthrough: the console, endpoint blocks, screen capture blocking, groups, email and Google Drive, S3 clean-up and reports.

---

## Support

* 📧 **Contact**: [vartul@zeroshield.ai](mailto:vartul@zeroshield.ai)
* 📧 **Support Queries**: [support@zeroshield.ai](mailto:support@zeroshield.ai)

---

> **Value Proposition:** ZeroShield DLP gives security teams one console and one set of policies to find sensitive data, stop it leaving through laptops, email, cloud apps and the network, clean up what is exposed in storage, and prove it to auditors, with each organisation's data kept private.

---

All rights reserved. This software and its documentation are the intellectual property of [ZeroShield](https://zeroshield.ai).
