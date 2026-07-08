# Installing the Wazuh Agent from Source on GNU Guix System

A step-by-step guide for building and running Wazuh agent v4.14.5 as a boot-persistent Shepherd service on Guix System 1.5.0.

**Tested environment:** Guix System 1.5.0 (x86_64) in VMware Workstation, Linux-libre 7.x kernel, Wazuh agent 4.14.5 built from source.

**Why from source?** Wazuh is not packaged in Guix, and Guix cannot install `.deb`/`.rpm` packages. The from-source method installs everything self-contained into `/var/ossec`, which works cleanly on Guix.

---

## Overview of the steps

1. Update Guix (`guix pull`) and fix the shell environment
2. Declare the `wazuh` user and group in `/etc/config.scm`
3. Install the build toolchain (GCC 13, not 15!)
4. Download and compile Wazuh 4.14.5
5. Enroll the agent with the manager
6. Add a Shepherd service for boot persistence
7. Reboot and verify

---

## Step 1 — Update Guix and set up the shell environment

Fresh installs run the guix from the ISO snapshot. Update it first (as root):

```bash
guix pull
```

After the pull completes, the shell still points at the **old** guix binary. Source the new profile:

```bash
GUIX_PROFILE="/root/.config/guix/current"
. "$GUIX_PROFILE/etc/profile"
hash guix
which guix     # must print /root/.config/guix/current/bin/guix
```

Make this permanent so every new session gets the right guix:

```bash
echo 'GUIX_PROFILE="/root/.config/guix/current"' >> /root/.bash_profile
echo '. "$GUIX_PROFILE/etc/profile"' >> /root/.bash_profile
```

### Troubleshooting this step

- **`Git error: SSL error: received early EOF`** during pull or reconfigure: transient network failure. Retry; git resumes from cache. If it recurs, clear the cache (`rm -rf ~/.cache/guix/checkouts`) or switch the VM network adapter from NAT to Bridged.
- **`commit X of channel 'guix' is not a descendant of Y`**: your shell is using an older guix than the one the system was built with. Re-source the profile as above. Only use `--allow-downgrades` as a last resort on a fresh system.

---

## Step 2 — Declare the wazuh user and group

The Wazuh installer runs `useradd`/`groupadd`, but on Guix System users are **declarative** — manually added accounts are wiped at the next `guix system reconfigure`. Declare them in `/etc/config.scm` instead.

Add `(gnu packages admin)` to the modules line at the top:

```scheme
(use-modules (gnu) (gnu packages admin) (gnu services shepherd))
```

Add a user account inside the `(users (cons* ...))` block:

```scheme
(user-account
  (name "wazuh")
  (group "wazuh")
  (system? #t)
  (comment "Wazuh agent")
  (home-directory "/var/ossec")
  (create-home-directory? #f)
  (shell (file-append shadow "/sbin/nologin")))
```

Add a `groups` field at the same level as `users` (right after it):

```scheme
;; System groups.
(groups (cons (user-group (name "wazuh") (system? #t))
              %base-groups))
```

Apply and verify:

```bash
guix system reconfigure /etc/config.scm
grep wazuh /etc/passwd /etc/group
```

---

## Step 3 — Install the build toolchain (use GCC 13)

**Critical:** Guix's default `gcc-toolchain` may be GCC 15, which fails to compile Wazuh's bundled `nlohmann/json.hpp` with errors like:

```
error: 'strtof' is not a member of 'std'
error: 'strtoull' is not a member of 'std'
```

Install GCC 13 explicitly along with the other tools:

```bash
guix install gcc-toolchain@13 make cmake curl wget tar gzip \
             pkg-config python automake autoconf libtool
```

Source the **package** profile (this is a different profile from the guix-pull one — you need both):

```bash
GUIX_PROFILE="/root/.guix-profile"
. "$GUIX_PROFILE/etc/profile"
which make gcc cmake    # all must resolve
gcc --version           # must report 13.x
```

Make it permanent:

```bash
echo 'GUIX_PROFILE="/root/.guix-profile"' >> /root/.bash_profile
echo '. "$GUIX_PROFILE/etc/profile"' >> /root/.bash_profile
```

> If you already attempted a build with GCC 15: `guix remove gcc-toolchain`, install `gcc-toolchain@13`, and **delete and re-extract the source tree** — CMake caches the old compiler path.

---

## Step 4 — Download and compile Wazuh

```bash
cd /tmp
wget https://github.com/wazuh/wazuh/archive/refs/tags/v4.14.5.tar.gz
tar xzf v4.14.5.tar.gz
cd wazuh-4.14.5
./install.sh
```

Answer the interactive prompts:

| Prompt | Answer |
|---|---|
| Language | `en` (or your preference) |
| Installation type | `agent` |
| Install location | Enter (accepts `/var/ossec`) |
| Manager IP | your Wazuh manager's IP |
| Integrity check (syscheck) | Enter (yes) |
| Rootkit detection (rootcheck) | Enter (yes) |
| Active response | Enter (yes) |

The compile takes 20–60 minutes on a typical 2-vCPU / 4 GB VM. Ignore the `egrep is obsolescent` warnings.

Success ends with a "Configuration finished properly" style banner. Start and check:

```bash
/var/ossec/bin/wazuh-control start
/var/ossec/bin/wazuh-control status
```

All five daemons should report running: `wazuh-modulesd`, `wazuh-logcollector`, `wazuh-syscheckd`, `wazuh-agentd`, `wazuh-execd`.

### Troubleshooting this step

- **`make: command not found`** at the "Running the Makefile" stage: the toolchain profile isn't sourced in this session. Re-run the two `GUIX_PROFILE`/source lines from Step 3 and rerun `./install.sh`.
- **`std::strtof` / `nlohmann/json.hpp` compile errors**: you're on GCC 15. Go back to Step 3, switch to GCC 13, delete and re-extract the source tree, rebuild.
- **Tip:** keep the tarball (or note this recipe) — `/tmp` is cleared on reboot and you'll want the same setup for future upgrades.

---

## Step 5 — Enroll with the manager

If the manager IP was set during install, check connectivity:

```bash
grep -i "connected to" /var/ossec/logs/ossec.log | tail -5
```

You want `Connected to the server (<MANAGER_IP>:1514)`. If the log shows `Unable to connect` instead, enroll and restart:

```bash
/var/ossec/bin/agent-auth -m <MANAGER_IP>
/var/ossec/bin/wazuh-control restart
```

The agent should appear as **Active** on the manager dashboard within a minute or two. Note: the agent version must not be newer than the manager version.

---

## Step 6 — Shepherd service for boot persistence

Guix has no systemd; services run under GNU Shepherd. Add this inside the `(list ...)` of your `(services (append (list ...) %desktop-services))` block in `/etc/config.scm`:

```scheme
;; Wazuh agent
(simple-service 'wazuh-agent shepherd-root-service-type
  (list (shepherd-service
          (documentation "Wazuh agent")
          (provision '(wazuh-agent))
          (requirement '(networking user-processes))
          (start #~(lambda _
                     (setenv "PATH" "/run/current-system/profile/bin:/run/current-system/profile/sbin")
                     (invoke "/var/ossec/bin/wazuh-control" "start")
                     #t))
          (stop #~(lambda _
                    (setenv "PATH" "/run/current-system/profile/bin:/run/current-system/profile/sbin")
                    (invoke "/var/ossec/bin/wazuh-control" "stop")
                    #f))
          (respawn? #f))))
```

**Two details that matter — both were discovered the hard way:**

1. **The `setenv "PATH" ...` lines are mandatory.** Shepherd starts services with an empty environment. `wazuh-control` is a shell script that calls `ps`, `grep`, `sed`, etc. by bare name; without PATH it exits 1 and the service is marked "failing."
2. **Parenthesis balance.** The block ends in `))))` — closing `respawn?`, `shepherd-service`, `list`, and `simple-service`. If reconfigure says `missing closing parenthesis`, count these. In vi, `%` on a paren jumps to its match.

Apply:

```bash
guix system reconfigure /etc/config.scm
```

### Troubleshooting this step

- **Service shows "stopped (failing)" while daemons are actually running**: the agent was already running when shepherd tried to start it, so `wazuh-control start` failed. This is a collision, not a real error.
- **`herd start wazuh-agent` keeps failing after fixing PATH in the config**: the *running* shepherd cannot hot-swap a service stuck in a failed state (reconfigure warns `some services could not be upgraded ... you will need to reboot`). The fix loads only after a reboot — Step 7.
- **Debug technique** — reproduce shepherd's environment manually to see the script's real error output:

  ```bash
  env -i PATH=/run/current-system/profile/bin:/run/current-system/profile/sbin \
      /var/ossec/bin/wazuh-control start
  ```

---

## Step 7 — Reboot and verify

Stop any manually-started agent first (avoids the start collision), then reboot so the new shepherd service definition loads:

```bash
/var/ossec/bin/wazuh-control stop
reboot
```

After boot:

```bash
herd status wazuh-agent          # expect: It is running
/var/ossec/bin/wazuh-control status   # expect: all five daemons running
```

Confirm the agent shows **Active** on the manager dashboard. From now on, manage the agent like any Guix service:

```bash
herd start wazuh-agent
herd stop wazuh-agent
herd status wazuh-agent
```

---

## Quick reference — pitfalls summary

| Symptom | Cause | Fix |
|---|---|---|
| `guix system` refuses: "not a descendant" | Shell using old guix after pull/reboot | Source `/root/.config/guix/current/etc/profile` |
| `Git error: SSL error: received early EOF` | Flaky network during channel fetch | Retry; clear `~/.cache/guix/checkouts`; try Bridged networking |
| `make: command not found` in install.sh | Package profile not sourced | Source `/root/.guix-profile/etc/profile` |
| `'strtof' is not a member of 'std'` | GCC 15 too strict for bundled headers | Use `gcc-toolchain@13`; re-extract source tree |
| wazuh user vanishes after reconfigure | Users are declarative on Guix | Declare user + group in `config.scm` |
| Shepherd service exits 1 | Empty PATH in shepherd environment | `setenv "PATH" ...` in start/stop lambdas |
| Fixed service still fails via herd | Live shepherd can't upgrade failed service | Reboot to load the new definition |
| `missing closing parenthesis` | Scheme paren mismatch | Block ends `))))`; use `%` in vi to match |

---

## Appendix — complete working /etc/config.scm skeleton

```scheme
(use-modules (gnu) (gnu packages admin) (gnu services shepherd))
(use-service-modules cups desktop networking ssh xorg)

(operating-system
  (locale "en_US.utf8")
  (timezone "Asia/Dhaka")
  (keyboard-layout (keyboard-layout "us" "altgr-intl"))
  (host-name "guix")

  (users (cons* (user-account
                  (name "guix")
                  (comment "Guix")
                  (group "users")
                  (home-directory "/home/guix")
                  (supplementary-groups '("wheel" "netdev" "audio" "video")))
                (user-account
                  (name "wazuh")
                  (group "wazuh")
                  (system? #t)
                  (comment "Wazuh agent")
                  (home-directory "/var/ossec")
                  (create-home-directory? #f)
                  (shell (file-append shadow "/sbin/nologin")))
                %base-user-accounts))

  ;; System groups.
  (groups (cons (user-group (name "wazuh") (system? #t))
                %base-groups))

  (services
   (append (list (service gnome-desktop-service-type)
                 (service openssh-service-type)

                 ;; Wazuh agent
                 (simple-service 'wazuh-agent shepherd-root-service-type
                   (list (shepherd-service
                           (documentation "Wazuh agent")
                           (provision '(wazuh-agent))
                           (requirement '(networking user-processes))
                           (start #~(lambda _
                                      (setenv "PATH" "/run/current-system/profile/bin:/run/current-system/profile/sbin")
                                      (invoke "/var/ossec/bin/wazuh-control" "start")
                                      #t))
                           (stop #~(lambda _
                                     (setenv "PATH" "/run/current-system/profile/bin:/run/current-system/profile/sbin")
                                     (invoke "/var/ossec/bin/wazuh-control" "stop")
                                     #f))
                           (respawn? #f))))

                 (set-xorg-configuration
                  (xorg-configuration (keyboard-layout keyboard-layout))))
           %desktop-services))

  (bootloader (bootloader-configuration
                (bootloader grub-bootloader)
                (targets (list "/dev/sda"))
                (keyboard-layout keyboard-layout)))
  (initrd-modules (append '("mptspi") %base-initrd-modules))
  (swap-devices (list (swap-space
                        (target (uuid "YOUR-SWAP-UUID")))))
  (file-systems (cons* (file-system
                         (mount-point "/")
                         (device (uuid "YOUR-ROOT-UUID" 'ext4))
                         (type "ext4"))
                       %base-file-systems)))
```

*Adjust usernames, UUIDs, keyboard layout, and desktop services to match your own system. Get UUIDs with `blkid`.*
