```
     /\___/\
     )     (    █████▄   ▄▄▄   ▄▄▄ ▄▄▄▄▄▄ ▄█████  ▄▄▄ ▄▄▄▄▄▄
    =\     /=   ██▄▄██▄ ██▀██ ██▀██  ██   ██     ██▀██  ██
      )   (     ██   ██ ▀███▀ ▀███▀  ██   ▀█████ ██▀██  ██
     /     \
     )     (    [#] Linux Privilege Escalation & Auto-Exploiter
    /       \
    \       /
     \__ __/
        ))
       //
      ((
       \)
```

Fast Linux privilege escalation auditor and exploitation toolkit written in C. Scans the local system for misconfigurations and links discovered binaries to built-in GTFOBins payloads to spawn root shells or read/write protected files on demand.

---

### Execution Flow

```
                  ┌──────────────────────┐
                  │    RootCat Engine    │
                  └──────────┬───────────┘
                             │
     ┌───────────────────────┼───────────────────────┐
     ▼                       ▼                       ▼
┌─────────────┐       ┌─────────────┐       ┌─────────────────┐
│ SUID Scan   │       │ Sudo Rules  │       │ Capabilities    │
│ (nftw walk) │       │ (NOPASSWD)  │       │ (getcap scan)   │
└──────┬──────┘       └──────┬──────┘       └────────┬────────┘
       │                     │                       │
       └────────────────┬────┴───────────────────────┘
                        │
                        ▼
       ┌─────────────────────────────────┐
       │   Cron & System File Auditor    │
       │   (/etc/passwd, /etc/shadow)    │
       └────────────────┬────────────────┘
                        │
                        ▼
       ┌─────────────────────────────────┐
       │     GTFOBins Match Engine       │
       └────────────────┬────────────────┘
                        │
                        ▼
       ┌─────────────────────────────────┐
       │  Interactive Exploitation Menu  │
       │  ├── [1] Spawn Root Shell       │
       │  ├── [2] Read Protected File    │
       │  ├── [3] Write Custom File      │
       │  └── [4] Execute Root Command   │
       └─────────────────────────────────┘
```

---

### Audit Modules

| Module | Target | Action |
|---|---|---|
| **SUID Crawler** | Entire filesystem or standard bins | Finds SUID binaries via `nftw` and matches them against GTFOBins |
| **Sudo Auditor** | `sudo -n -l` | Checks for `NOPASSWD:` entries that can be abused |
| **Cap Auditor** | `getcap -r /` | Detects `cap_setuid`, `cap_dac_override`, and `cap_sys_admin` |
| **Cron Auditor** | `/etc/crontab`, `/etc/cron.d/` | Finds wildcard expansion bugs in scheduled root tasks |
| **System Files** | `/etc/passwd`, `/etc/shadow` | Verifies write permissions on password files and shadow read access |

---

### Flags

| Flag | Long Flag | Description |
|---|---|---|
| `-h` | `--help` | Show the help screen |
| `-f` | `--fastmode` | Fast scan mode (checks standard bin paths: `/usr/bin`, `/bin`, `/usr/local/bin`, `/usr/sbin`, `/sbin`) |
| `-v` | `--verbose` | Show verbose output and unmatched SUID binaries |
| `-p <PATH>` | `--path <PATH>` | Set custom target path for the crawler (defaults to `/`) |

---

### Build & Install

```bash
git clone https://github.com/love4starve/RootCat.git
cd RootCat
make
```

Build a stripped, optimized release binary:

```bash
make release
```

---

### Usage Examples

Standard full system scan:
```bash
./rootcat
```

Fast scan (bins only) with verbose output:
```bash
./rootcat -f -v
```

Scan a specific mount or directory:
```bash
./rootcat -p /opt
```
