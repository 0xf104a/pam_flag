# PAM flagging module
This PAM module allows to create flag for a user who recently authenticated. 
The general purpose to flag recently authenticated users is to direct them to easier
authentication methods(e.g. fingerprint) instead blindly granting, say sudo, for some time.

## Why do you need this?
In my setting I don't want to grant sudo with no authentication under any circumstances.
Luckily, enough I have a fingerprint reader on my laptop. So instead of entering password each time
I may use just fingerprint which is much faster. 
Though fingerprint is less secure than password and I do not want rely on it completely. 
So the thing I wanted to replace sudo grace periods with sudo just asking for fingerprint.

But that is not that easy with existing modules: you either use password, fingerprint or both.
So I designed this module to direct authentication towards different methods based on 
whether I have recently entered password or not. Using this module I have just disabled grace periods
for sudo and now I allow PAM handle all timeouts and directing authentication methods.

# Installation
## Building
To compile you would need `cmake`, `make` and `libpam` that is perhaps already installed and its headers which are usually called
`libpam-devel` or something alike depending on your distribution.
The compilation is straighforward with `cmake`:
```bash
cmake .
make
```
## Installing module
To install the module you need to copy it to `/usr/lib/security` or `/lib/security` (depending on distro) directory.
You can do it with `install` command:
```bash
sudo install -o root -g root -m 0644 pam_flag.so /usr/lib/security/pam_flag.so
```
After installing modify config to your choosing.

**Don't forget to update your MAC(AppArmor, SELinux, etc) rules/policies to allow respective utilites/programs
to read-write to `/run/pam-flag/` directory.**

# Usage
## mode
The module has two operating modes:
* `set` - sets flag, should be invoked when strong authentication succeeds
* `require` - requires flag to be set, fails if flag is not set
The mode is passed as `mode` parameter.
## timeout
An integer value in seconds. Descibes after which time the flag is invalidated.
In other words, it is an actual flag time-to-live.
If timeout is negative, it is ignored and flag is never invalidated.
## Example
This example shows how you can direct authentication towards less secure but easier method if flag is present
and towards secure method if flag is missing.
```
# --- Route based on flag ---
# If flag present: don't jump (we'll try fingerprint next).
# If flag missing: jump over fingerprint to secure auth.
auth    [success=ignore default=1] pam_flag.so mode=require timeout=600

# --- Less-secure path (only reached when flag is present) ---
# If fingerprint succeeds, we stop here and accept.
auth    sufficient                 pam_fprintd.so

# --- Secure path (always taken when flag is missing; fallback when fingerprint fails) ---
auth    requisite                  pam_unix.so try_first_pass nullok

# After a successful secure auth, set the flag (fingerprint-success won't reach this line).
auth    optional                   pam_flag.so mode=set timeout=600

# Account
account required                   pam_unix.so

# Session
session required                   pam_limits.so
session required                   pam_unix.so
```

# How flags are stored?
Flags are empty files in `/run/pam-flag/` directory. 
When `mode=set` is invoked the file is created or its last update timestamp is modified.
When `mode=require` is invoked the files modifciation time is checked. If it was more then `timeout` seconds ago,
the file is considered invalid and the module fails. If file does not exist, the module also fails.
Each flag is identified by the user's numeric UID (file name equals the UID).