# One-Time Privilege Approval

**This project is under development and only provide a very naive, hardcoded sketch for the core functionality. Discussion is welcomed but no change are guaranteed. The author accepts no feature requests or suggestions until fully completed.**

## Description

One-Time Privilege Approval (OTPA) aims to create a channel for non-sudo users to apply for an one-time approval of executing commands with sudo privilege. 

OTPA uses email communication between the system and the administrator. The administrator can reply to the email with a specific string plus a TOTP for approval.

The two non-sudo user-side commands are:
* request-privilege [command][-f command-file-path]
* run-approved [ID] [digest] [OTP]

The pipeline of this project is as follows:
1. Non-sudo user applies to run command with sudo privilege using `request-privilege` command
2. The system sends an email to the specified address, listing the absolute-path style commands in the order claimed by the non-sudo user, the approval string and the rejection string.
3. The system administrator replies to the email with the approval string plus the appointed TOTP or rejection string.
4. Upon receiving an approval email, the system checks if the ID and the digest match, and if the TOTP is valid. 
5. Once the check is passed, the non-sudo user uses `run-approved` to invoke the system-owned sudo broker to run the listed commands with sudo privilege

## Installation

### Required Environment
Use `sudo apt install` to install the following required packages:
* python3
* msmtp
* oathtool
* jq

Additionally, the non-sudo user group that has access to `request-approval` and `run-approved` commands is hardcoded `privilege-requesters`. Create this user group with 
```bash
sudo groupadd --system privilege-requesters
```
and add the existing user into this group to enable their access.

The project requires the following directories. Create them using the following commands:
```bash
sudo install -d -o root -g root -m 0750 /etc/privilege-approval
sudo install -d -o root -g root -m 0750 /usr/local/libexec/privilege-approval

sudo install -d -o root -g root -m 0750 /var/lib/privilege-approval
sudo install -d -o root -g root -m 0750 /var/lib/privilege-approval/pending
sudo install -d -o root -g root -m 0750 /var/lib/privilege-approval/approved
sudo install -d -o root -g root -m 0750 /var/lib/privilege-approval/running
sudo install -d -o root -g root -m 0750 /var/lib/privilege-approval/done
sudo install -d -o root -g root -m 0750 /var/lib/privilege-approval/rejected
sudo install -d -o root -g root -m 0750 /var/lib/privilege-approval/locks

sudo install -d -o root -g root -m 0750 /var/log/privilege-approval
sudo install -d -o root -g root -m 0700 /var/log/sudo-io/privilege-approval

sudo install -d -o root -g root -m 0750 /etc/privilege-approval/users.d
```

## Configurations

**Administrator configuration.** Edit the file `admin-config.env` to configure administrator email, SMTP and IMAP entries, and basic configs, then copy the content into `/etc/privilege-approval/config.env`, finally protect the file by changing the ownership and mod.
```bash
sudo chown root:root /etc/privilege-approval/config.env
sudo chmod 0640 /etc/privilege-approval/config.env
```

**User configuration.** Edit the file `user-config.env` to configure user email. Then create a file `<username>.env` under `/etc/privilege-approval/users.d` with the content the edited `user-config.env`.

## Create TOTP

Create a TOTP secret with the following command
```bash
SECRET="$(python3 - <<'PY'
import base64, secrets
print(base64.b32encode(secrets.token_bytes(20)).decode().rstrip("="))
PY
)"
echo "$SECRET"
```
Then save and protect it with
```bash
sudo bash -c "echo '$SECRET' > /etc/privilege-approval/totp.secret"
sudo chown root:root /etc/privilege-approval/totp.secret
sudo chmod 0600 /etc/privilege-approval/totp.secret
```

Copy the secret to the administrator's authencator app, and test it by comparing the OTP on the app and the one returned by the following command:
```bash
sudo oathtool --totp -b "$(sudo cat /etc/privilege-approval/totp.secret)"
```

## Installation

1. Copy the content in `common.py` into `/usr/local/libexec/privilege-approval/common.py`, then protect it with 
```bash
sudo chown root:root /usr/local/libexec/privilege-approval/common.py
sudo chmod 0755 /usr/local/libexec/privilege-approval/common.py
```
2. Copy the content in `request_backend.py` into `/usr/local/libexec/privilege-approval/request_backend.py`, and protect it with
```bash
sudo chown root:root /usr/local/libexec/privilege-approval/request_backend.py
sudo chmod 0755 /usr/local/libexec/privilege-approval/request_backend.py
```
3. Copy the content in `check_replies.py` into `/usr/local/libexec/privilege-approval/check_replies.py`, and protect it with 
```bash
sudo chown root:root /usr/local/libexec/privilege-approval/check_replies.py
sudo chmod 0755 /usr/local/libexec/privilege-approval/check_replies.py
```
4. Copy the content in `run_approved.py` into `/usr/local/libexec/privilege-approval/run_backend.py`, and protect it with 
```bash
sudo chown root:root /usr/local/libexec/privilege-approval/run_backend.py
sudo chmod 0755 /usr/local/libexec/privilege-approval/run_backend.py
```
5. Copy the content in `request-privilege.sh` into `/usr/local/bin/request-privilege`; Copy the content in `run-approved.sh` into `/usr/local/bin/run-approved`. Protect them with
```bash
sudo chown root:root /usr/local/bin/request-privilege /usr/local/bin/run-approved
sudo chmod 0755 /usr/local/bin/request-privilege /usr/local/bin/run-approved
```
6. Edit the sudoers profile for `privilege-requesters` group with `sudo visudo -f /etc/sudoers.d/privilege-approval` command. Copy the content in `privilege-approval-sudoer` into this profile.
7. Create privilege approval checker service by copying the content in `privilege-approval-check.service` into `/etc/systemd/system/privilege-approval-check.service` and the content in `privilege-approval-check.path` into `/etc/systemd/system/privilege-approval-check.path`, then enable the service with
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now privilege-approval-check.path
```
8. Copy the content in `cleanup_history.py` into `/usr/local/libexec/privilege-approval/cleanup_history.py`, and protect it with
```bash
sudo chown root:root /usr/local/libexec/privilege-approval/cleanup_history.py
sudo chmod 0755 /usr/local/libexec/privilege-approval/cleanup_history.py
```
9. Create a timed history cleanup service by copying the content in `privilege-approval-cleanup.service` into `/etc/systemd/system/privilege-approval-cleanup.service` and the content in `privilege-approval-cleanup.timer` into `/etc/systemd/system/privilege-approval-cleanup.timer`, then enable the service with 
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now privilege-approval-cleanup.timer
```

## Upcoming Changes

The OTP for run-approved command seems unnecessary. Once a request is approved, the system should create a random, dedicated OTP that does not change over time and send it to the requester, so that the requester does not need to consume the approval immediately due to the OTP expiration. However, a time frame should also be specified after a request is approved. If the approval is not consumed within the time limit, it will expire.

Such tedious installation steps screams for a installation and uninstallation script.

A administrator-side and user-side configuration prompt is also useful.

A better way to manage the path is also necessary. Ideally, not only the commands should be in the absolute path style (as already implemented), the path involved in the command args should also be converted to absolute paths if it is not so.