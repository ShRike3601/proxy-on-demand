"""Proxy on demand.

Start: launches a fresh EC2 server that installs Shadowsocks on first boot,
points the local sing-box config at its new public IP, and starts sing-box.
Stop:  stops sing-box, then terminates the server. Termination releases the public IP
and deletes the disk, so nothing keeps billing.

AWS access: the stored key (DPAPI-encrypted) can only assume one role, and only with a
6-digit MFA code from your phone. The resulting 1-hour credentials live in memory only.
The Shadowsocks password lives only in the local sing-box config (created with a random
password) and is never shown. See README.md.
"""
import base64
import configparser
import ctypes
import hashlib
import io
import json
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from tkinter import font as tkfont, messagebox, scrolledtext, simpledialog, ttk

__version__ = "1.1.0"
REPO = "ShRike3601/proxy-on-demand"  # GitHub repo, for the "new version available" notice
ROLE_NAME = "proxy-on-demand-role"  # IAM role holding the app's EC2 permissions; assumable only with MFA
SESSION_SECONDS = 3600              # temporary credentials last 1 hour, in memory only
OLD_PROFILE = "proxy-on-demand"     # plain-text profile used by earlier versions; removed on first save
APP_TAG = "ss-proxy-app"          # every resource we create is tagged app=ss-proxy-app
INSTANCE_TYPE = "t3.micro"
PORT = 443
METHOD = "2022-blake3-aes-128-gcm"
SS_VERSION = "1.25.0"
SG_NAME = "ss-proxy-sg"
AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"

# Not %LOCALAPPDATA%: the Microsoft Store build of Python silently redirects writes there into its own
# package folder, where you can't find them and where sing-box (not a Store app) can't read its config.
APP_DIR = os.path.join(os.path.expanduser("~"), ".proxy-on-demand")
OLD_APP_DIR = os.path.join(os.environ.get("LOCALAPPDATA", ""), "proxy-on-demand")  # earlier versions
APP_LOG = os.path.join(APP_DIR, "app.log")
SETTINGS_FILE = os.path.join(APP_DIR, "settings.json")
USAGE_FILE = os.path.join(APP_DIR, "usage.json")  # this month's servers, for the data allowance
DEFAULT_SETTINGS = {"mfa": True, "region": "ap-south-1", "ssm_role": "",  # MFA on unless the user opts out
                    "max_hours": 12, "allow_over": False}  # allow_over: let data go past the free 100 GB
KEY_FILE = os.path.join(APP_DIR, "aws-key.bin")  # DPAPI-encrypted, readable only by this Windows user
DPAPI_ENTROPY = b"proxy-on-demand/aws-key/v1"
PLAINTEXT_CRED_FILE = os.environ.get("AWS_SHARED_CREDENTIALS_FILE") or \
    os.path.join(os.path.expanduser("~"), ".aws", "credentials")
SB_DIR = SB_HOME = os.path.join(APP_DIR, "sing-box")  # sing-box.exe, its config and its log
SB_CONFIG = os.path.join(SB_DIR, "config.json")
SB_LOG = os.path.join(SB_DIR, "sing-box.log")
SB_VERSION = "1.14.4"
SB_ZIP_SHA256 = "99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df"  # official windows-amd64 zip
WARP_CLI = r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe"
MAX_HOURS = 12                    # default auto-delete time; users pick 1..MAX_HOURS_LIMIT on the main window
MAX_HOURS_LIMIT = 24
HOURLY_USD = 0.018                # t3.micro + public IPv4 + 8 GB disk (ap-south-1), excluding data transfer
KEEP_FAILED_SERVER = False        # True keeps a server whose Start failed (for debugging); it then bills until Stop
NO_WINDOW = 0x08000000


# ---------- local side: sing-box ----------

def load_config(path=SB_CONFIG):
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)


def write_json(path, data):
    """Atomic write, UTF-8 without BOM (sing-box rejects a BOM)."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def ss_outbound(cfg):
    return next(o for o in cfg["outbounds"] if o.get("tag") == "ss-out")


def default_config(password):
    """The working setup: system-wide TUN, everything via Shadowsocks, DNS over TLS through the tunnel."""
    return {
        "log": {"timestamp": True, "level": "info"},
        "dns": {"servers": [{"tag": "cloudflare", "type": "tls", "server": "1.1.1.1", "server_port": 853,
                             "tls": {"enabled": True, "server_name": "cloudflare-dns.com"}, "detour": "ss-out"}],
                "final": "cloudflare", "strategy": "ipv4_only"},
        "inbounds": [{"type": "tun", "tag": "tun-in", "interface_name": "sing-tun",
                      "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"], "mtu": 1400, "stack": "system",
                      "auto_route": True, "strict_route": True,
                      "route_exclude_address": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                                "fc00::/7", "fe80::/10"]}],
        "outbounds": [{"type": "shadowsocks", "tag": "ss-out", "server": "0.0.0.0", "server_port": PORT,
                       "method": METHOD, "password": password}],
        "route": {"auto_detect_interface": True, "final": "ss-out",
                  # sniff first so only real DNS is hijacked; a bare hijack-dns rule swallows all traffic
                  "rules": [{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"}]},
    }


def ensure_config(path=SB_CONFIG):
    """Create a config with a fresh random password if none exists. Returns True if created."""
    if os.path.exists(path):
        return False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    write_json(path, default_config(base64.b64encode(os.urandom(16)).decode()))  # 16-byte key for aes-128
    return True


def set_server(ip, path=SB_CONFIG):
    """Point the ss-out outbound at ip, keeping one backup of the original."""
    cfg = load_config(path)
    ss_outbound(cfg)["server"] = ip
    backup = path + ".app-backup"
    if not os.path.exists(backup):
        shutil.copy2(path, backup)
    write_json(path, cfg)


def warp(*args):
    if not os.path.exists(WARP_CLI):
        return ""
    return subprocess.run([WARP_CLI, *args], capture_output=True, text=True, creationflags=NO_WINDOW).stdout


def warp_connected():
    return re.search(r"Status update:\s*Connected", warp("status")) is not None


def warp_disconnect():
    warp("disconnect")
    for _ in range(20):
        if not warp_connected():
            return
        time.sleep(0.5)
    raise RuntimeError("Could not disconnect Cloudflare WARP. Turn it off by hand and press Start again.")


def find_singbox():
    exe = os.path.join(SB_HOME, "sing-box.exe")
    return exe if os.path.exists(exe) else None


def install_singbox(log):
    """Download the official sing-box release, verify its pinned SHA-256, unpack into SB_HOME."""
    url = (f"https://github.com/SagerNet/sing-box/releases/download/v{SB_VERSION}/"
           f"sing-box-{SB_VERSION}-windows-amd64.zip")
    log(f"Downloading sing-box {SB_VERSION} (official release, about 33 MB, one time)")
    with urllib.request.urlopen(url, timeout=120) as r:
        data = r.read()
    if hashlib.sha256(data).hexdigest() != SB_ZIP_SHA256:
        raise RuntimeError("The sing-box download did not match its expected checksum, so it was not installed.")
    os.makedirs(SB_HOME, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for entry in z.infolist():
            name = os.path.basename(entry.filename)  # basename only: nothing can be written outside SB_HOME
            if name:
                with open(os.path.join(SB_HOME, name), "wb") as f:
                    f.write(z.read(entry))
    return os.path.join(SB_HOME, "sing-box.exe")


# ---------- settings and AWS key ----------

def migrate_old_files(old=OLD_APP_DIR, new=APP_DIR):
    """Carry the saved key and settings over from the old location. Returns the names copied."""
    copied = []
    for name in ("aws-key.bin", "settings.json"):
        src, dst = os.path.join(old, name), os.path.join(new, name)
        if os.path.exists(src) and not os.path.exists(dst):
            os.makedirs(new, exist_ok=True)
            shutil.copy2(src, dst)
            copied.append(name)
    return copied


def load_settings(path=SETTINGS_FILE):
    try:
        with open(path, encoding="utf-8") as f:
            saved = json.load(f)
    except (OSError, ValueError):
        saved = {}
    s = {**DEFAULT_SETTINGS, **{k: v for k, v in saved.items() if k in DEFAULT_SETTINGS}}
    s["max_hours"] = clamp_hours(s["max_hours"])
    return s


def clamp_hours(value):
    try:
        return min(MAX_HOURS_LIMIT, max(1, int(value)))
    except (TypeError, ValueError):
        return DEFAULT_SETTINGS["max_hours"]


def save_settings(changes, path=SETTINGS_FILE):
    """Merge changes into the saved settings (other keys are kept)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    write_json(path, {**load_settings(path), **changes})


def valid_region(region):
    return re.fullmatch(r"[a-z]{2}(-[a-z]+)+-\d", region) is not None


def validate_key(key_id, secret):
    if not re.fullmatch(r"AKIA[A-Z0-9]{16}", key_id):
        raise ValueError("The access key ID should be 20 characters starting with AKIA.")
    if len(secret) != 40 or not re.fullmatch(r"[A-Za-z0-9/+=]+", secret):
        raise ValueError("The secret access key should be 40 characters.")


# With MFA (default): the stored key can do nothing except assume ROLE_NAME, and the role demands a
# fresh MFA code. The resulting 1-hour credentials live only in memory.
# Without MFA (opt-out): the key's own user holds the least-privilege EC2 policy and is used directly.
# Either way the key is encrypted on disk with Windows DPAPI: unreadable from a copied disk, backup or
# cloud sync. (Malware running as you could still decrypt it - which is what MFA protects against.)

class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data, protect):
    buf = ctypes.create_string_buffer(data, len(data))
    ent = ctypes.create_string_buffer(DPAPI_ENTROPY, len(DPAPI_ENTROPY))
    blob_in = _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_ent = _Blob(len(DPAPI_ENTROPY), ctypes.cast(ent, ctypes.POINTER(ctypes.c_char)))
    blob_out = _Blob()
    fn = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
    if not fn(ctypes.byref(blob_in), None, ctypes.byref(blob_ent), None, None, 0x1,  # 0x1: never show UI
              ctypes.byref(blob_out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def save_key(record, path=KEY_FILE):
    """record: key_id, secret, mfa_serial, role_arn. Written DPAPI-encrypted, atomically."""
    validate_key(record["key_id"], record["secret"])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(_dpapi(json.dumps(record).encode(), protect=True))
    os.replace(tmp, path)
    remove_plaintext_profile()


def load_key(path=KEY_FILE):
    try:
        with open(path, "rb") as f:
            return json.loads(_dpapi(f.read(), protect=False))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        raise RuntimeError("The saved AWS key could not be decrypted (was it copied from another "
                           "Windows account?). Enter it again in AWS settings.") from e


def remove_plaintext_profile(path=PLAINTEXT_CRED_FILE):
    """Earlier versions stored the key in plain text in the AWS credentials file; remove only that profile."""
    cp = configparser.RawConfigParser()
    try:
        cp.read(path, encoding="utf-8")
    except configparser.Error:
        return
    if cp.remove_section(OLD_PROFILE):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            cp.write(f)
        os.replace(tmp, path)


def assume(record, code, region):
    """Trade the stored key + MFA code for 1-hour credentials. Returns a boto3 Session and its expiry."""
    import boto3
    from botocore.exceptions import ClientError
    if not re.fullmatch(r"\d{6}", code or ""):
        raise ValueError("The MFA code is the 6-digit number from your authenticator app.")
    sts = boto3.Session(aws_access_key_id=record["key_id"], aws_secret_access_key=record["secret"],
                        region_name=region).client("sts")
    try:
        c = sts.assume_role(RoleArn=record["role_arn"], RoleSessionName="proxy-on-demand",
                            SerialNumber=record["mfa_serial"], TokenCode=code,
                            DurationSeconds=SESSION_SECONDS)["Credentials"]
    except ClientError as e:
        raise RuntimeError("AWS refused the sign-in. Either the MFA code was wrong or expired (wait for the "
                           f"next code), or the role {ROLE_NAME} is missing or does not trust this user "
                           f"(README, step 7).\n\nAWS said: {e.response['Error']['Message']}") from e
    session = boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
                            aws_session_token=c["SessionToken"], region_name=region)
    return session, c["Expiration"]


def key_session(record):
    """No-MFA mode: use the stored key directly."""
    import boto3
    return boto3.Session(aws_access_key_id=record["key_id"], aws_secret_access_key=record["secret"])


def inspect_key(key_id, secret, mfa=True, region=DEFAULT_SETTINGS["region"]):
    """Look up who the key belongs to (and its MFA device, in MFA mode). Returns (record, warnings);
    raises if the key is unusable."""
    import boto3
    from botocore.exceptions import ClientError
    validate_key(key_id, secret)
    s = boto3.Session(aws_access_key_id=key_id, aws_secret_access_key=secret, region_name="us-east-1")
    try:
        arn = s.client("sts").get_caller_identity()["Arn"]
    except ClientError as e:
        raise RuntimeError(f"AWS does not accept this key: {e.response['Error']['Message']}") from e
    if ":user/" not in arn:
        raise RuntimeError("This is a root key. Never use root keys: delete it and create the IAM user "
                           "described in the README instead.")
    account, user = arn.split(":")[4], arn.split("/")[-1]
    warnings = []
    try:
        s.client("iam").list_users(MaxItems=1)
        warnings.append("This key has admin rights. If it leaked, anyone could use your whole AWS account. "
                        "Use the dedicated user from the README, which can do nothing without your MFA code.")
    except ClientError:
        pass
    record = {"key_id": key_id, "secret": secret, "user_arn": arn}
    if not mfa:
        try:
            s.client("ec2", region_name=region).describe_instances(MaxResults=5)
        except ClientError:
            warnings.append(f"This key cannot use EC2 in {region}. Attach the policy from "
                            "'Copy user policy' to this user (README, setup without MFA).")
        return record, warnings
    try:
        devices = s.client("iam").list_mfa_devices(UserName=user)["MFADevices"]
    except ClientError as e:
        raise RuntimeError("This key cannot look up its MFA device. Attach the key policy "
                           "(AWS settings > Copy user policy) to this user.") from e
    if not devices:
        raise RuntimeError(f"The user {user} has no MFA device. Add a virtual MFA device to it (README, step 6), "
                           "or untick 'Require MFA' in AWS settings.")
    record.update(mfa_serial=devices[0]["SerialNumber"], role_arn=f"arn:aws:iam::{account}:role/{ROLE_NAME}")
    return record, warnings


def key_policy():
    """For the IAM user that owns the stored key: it can only assume the app role and find its own MFA device."""
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "AssumeAppRoleOnly", "Effect": "Allow", "Action": "sts:AssumeRole",
         "Resource": f"arn:aws:iam::*:role/{ROLE_NAME}"},
        {"Sid": "FindOwnMfaDevice", "Effect": "Allow", "Action": "iam:ListMFADevices",
         "Resource": "arn:aws:iam::*:user/${aws:username}"}]}


def trust_policy(user_arn):
    """For the app role: only this one user, only with MFA used in the last hour. Naming the user (not the
    whole account) matters: any identity that can create MFA devices could otherwise satisfy an MFA check."""
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": user_arn}, "Action": "sts:AssumeRole",
         "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"},
                       "NumericLessThan": {"aws:MultiFactorAuthAge": "3600"}}}]}


def iam_policy(region, ssm_role=""):
    """Least-privilege policy for the app: tagged t3.micro from Amazon images in one region, nothing else."""
    ec2 = f"arn:aws:ec2:{region}:*:"
    statements = [
        {"Sid": "ReadAndCreateSg", "Effect": "Allow",
         "Action": ["ec2:DescribeInstances", "ec2:DescribeVolumes", "ec2:DescribeVpcs", "ec2:DescribeSubnets",
                    "ec2:DescribeSecurityGroups", "ec2:CreateSecurityGroup",
                    "cloudwatch:GetMetricStatistics"],  # read-only: how much data the app's servers sent
         "Resource": "*", "Condition": {"StringEquals": {"aws:RequestedRegion": region}}},
        {"Sid": "LaunchOnlyTaggedT3Micro", "Effect": "Allow", "Action": "ec2:RunInstances",
         "Resource": ec2 + "instance/*",
         "Condition": {"StringEquals": {"ec2:InstanceType": INSTANCE_TYPE, "aws:RequestTag/app": APP_TAG}}},
        {"Sid": "LaunchOnlyAmazonImages", "Effect": "Allow", "Action": "ec2:RunInstances",
         "Resource": f"arn:aws:ec2:{region}::image/*", "Condition": {"StringEquals": {"ec2:Owner": "amazon"}}},
        {"Sid": "LaunchSupportingResources", "Effect": "Allow", "Action": "ec2:RunInstances",
         "Resource": [ec2 + t for t in ("subnet/*", "network-interface/*", "security-group/*", "volume/*")]},
        {"Sid": "TagOnlyAtCreation", "Effect": "Allow", "Action": "ec2:CreateTags", "Resource": "*",
         "Condition": {"StringEquals": {"ec2:CreateAction": ["RunInstances", "CreateSecurityGroup"]}}},
        {"Sid": "OnlyAppResources", "Effect": "Allow",
         "Action": ["ec2:TerminateInstances", "ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress"],
         "Resource": "*", "Condition": {"StringEquals": {"ec2:ResourceTag/app": APP_TAG}}},
        {"Sid": "LatestAmazonLinuxAmi", "Effect": "Allow", "Action": "ssm:GetParameter",
         "Resource": f"arn:aws:ssm:{region}::parameter/aws/service/ami-amazon-linux-latest/*"},
    ]
    if ssm_role:
        statements.append({"Sid": "PassSessionManagerRole", "Effect": "Allow", "Action": "iam:PassRole",
                           "Resource": f"arn:aws:iam::*:role/{ssm_role}",
                           "Condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}})
    return {"Version": "2012-10-17", "Statement": statements}


class NoKeyError(RuntimeError):
    pass


class SignInCancelled(RuntimeError):
    pass


def singbox_running():
    out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq sing-box.exe", "/NH"],
                         capture_output=True, text=True, creationflags=NO_WINDOW).stdout
    return "sing-box.exe" in out


def stop_singbox():
    subprocess.run(["taskkill", "/IM", "sing-box.exe", "/F"],
                   capture_output=True, creationflags=NO_WINDOW)
    for _ in range(20):
        if not singbox_running():
            return
        time.sleep(0.5)


def start_singbox(exe):
    os.makedirs(SB_DIR, exist_ok=True)
    log = open(SB_LOG, "w", encoding="utf-8")
    proc = subprocess.Popen([exe, "run", "-c", SB_CONFIG], stdout=log, stderr=subprocess.STDOUT,
                            creationflags=NO_WINDOW)
    time.sleep(4)
    if proc.poll() is not None:
        raise RuntimeError(f"sing-box exited immediately (code {proc.returncode}). See {SB_LOG}")


def egress_ip():
    with urllib.request.urlopen("https://api.ipify.org", timeout=10) as r:
        return r.read().decode().strip()


IP_SERVICES = ("https://checkip.amazonaws.com", "https://api.ipify.org", "https://ipv4.icanhazip.com")


def my_ips(rounds=3):
    """All public IPv4 addresses your network uses (call while sing-box is stopped). Campus and office
    networks often spread connections over several public IPs, so ask several services several times."""
    found = set()
    for _ in range(rounds):
        for url in IP_SERVICES:
            try:
                with urllib.request.urlopen(url, timeout=5) as r:
                    ip = r.read().decode().strip()
                socket.inet_aton(ip)  # skip anything that is not an IPv4 address
                if ip.count(".") == 3:
                    found.add(ip)
            except (OSError, ValueError):
                pass
    if not found:
        raise RuntimeError("Could not find your public IP address. Check your internet connection.")
    return found


# ---------- server side: EC2 ----------

DATA_CAP_SCRIPT = r"""cat > /usr/local/bin/data-cap.sh <<'EOF'
#!/bin/bash
# Powers this server off (which deletes it) once it has sent LIMIT bytes: the free data left this month.
IF=$(ip -o route show default | awk '{print $5; exit}')
while sleep 5; do
  if [ "$(cat /sys/class/net/$IF/statistics/tx_bytes)" -ge LIMIT ]; then
    logger -t data-cap "monthly free data used up: shutting down"; systemctl poweroff
  fi
done
EOF
chmod 755 /usr/local/bin/data-cap.sh
cat > /etc/systemd/system/data-cap.service <<'EOF'
[Unit]
Description=Stop this server when its data allowance is used up
[Service]
ExecStart=/usr/local/bin/data-cap.sh
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now data-cap
"""


def user_data(password, max_hours=MAX_HOURS, cap_bytes=0):
    """First-boot script: install shadowsocks-rust (checksum-verified) and run it as a service.
    cap_bytes > 0: the server powers itself off after sending that many bytes (0 = no data cap)."""
    max_hours = clamp_hours(max_hours)
    cap = DATA_CAP_SCRIPT.replace("LIMIT", str(int(cap_bytes))) if cap_bytes > 0 else ""
    ss_conf = json.dumps({"server": "0.0.0.0", "server_port": PORT, "password": password,
                          "method": METHOD, "mode": "tcp_and_udp"})
    # musl = statically linked: the -gnu build needs a newer glibc than Amazon Linux 2023 ships and crash-loops
    f = f"shadowsocks-v{SS_VERSION}.x86_64-unknown-linux-musl.tar.xz"
    url = f"https://github.com/shadowsocks/shadowsocks-rust/releases/download/v{SS_VERSION}/{f}"
    # Heredoc bodies are not echoed by `set -x`, so the password stays out of the console log.
    return f"""#!/bin/bash
set -euxo pipefail
exec > >(tee /var/log/ss-setup.log > /dev/console) 2>&1
# safety net first, so it holds even if setup fails: launched with shutdown-behavior=terminate,
# this ends all billing after {max_hours} h even if Stop is never pressed
shutdown -h +{max_hours * 60}
{cap}cd /tmp
command -v xz || dnf install -y xz
curl -fsSL --retry 5 -O {url} -O {url}.sha256
sha256sum -c {f}.sha256
tar -xJf {f} -C /usr/local/bin ssserver
/usr/local/bin/ssserver --version  # fails setup right here if the binary cannot run on this system
useradd --system --no-create-home --shell /sbin/nologin shadowsocks || true
install -d -m 750 -g shadowsocks /etc/shadowsocks-rust
cat > /etc/shadowsocks-rust/config.json <<'EOF'
{ss_conf}
EOF
chgrp shadowsocks /etc/shadowsocks-rust/config.json
chmod 640 /etc/shadowsocks-rust/config.json
cat > /etc/systemd/system/shadowsocks-server.service <<'EOF'
[Unit]
Description=Shadowsocks server
After=network-online.target
Wants=network-online.target

[Service]
User=shadowsocks
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/ssserver -c /etc/shadowsocks-rust/config.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now shadowsocks-server
# "started" is not "working": only report success once the server really listens on the port
for i in $(seq 30); do ss -ltn | grep -q ':{PORT} ' && break; sleep 1; done
ss -ltn | grep -q ':{PORT} ' || {{ journalctl -u shadowsocks-server -n 20 --no-pager; echo SS-SETUP-FAILED; exit 1; }}
echo SS-SETUP-DONE
"""


class Aws:
    def __init__(self, log, settings, session):
        self.region, self.ssm_role = settings["region"], settings["ssm_role"]
        self.ec2 = session.client("ec2", region_name=self.region)
        self.ssm = session.client("ssm", region_name=self.region)
        self.cw = session.client("cloudwatch", region_name=self.region)
        self.log = log

    def sent_bytes(self, iid, since, until):
        """Bytes the server sent out between since and until (AWS CloudWatch NetworkOut; updates every 5 min)."""
        points = self.cw.get_metric_statistics(
            Namespace="AWS/EC2", MetricName="NetworkOut", Dimensions=[{"Name": "InstanceId", "Value": iid}],
            StartTime=since, EndTime=until, Period=3600, Statistics=["Sum"])["Datapoints"]
        return sum(p["Sum"] for p in points)

    def month_usage(self, ledger, now=None):
        """Data sent this calendar month (UTC) by every server this app launched, terminated ones included.
        CloudWatch keeps hourly figures for 63 days, so a server that deleted itself still counts."""
        now = now or datetime.now(timezone.utc)
        start = month_start(now)
        oldest = (start - timedelta(hours=MAX_HOURS_LIMIT)).isoformat()  # may have run into this month
        # shortcut: servers in a region you switched away from this month aren't counted; the budget alert still is
        ids = [iid for iid, info in ledger["instances"].items()
               if info["region"] == self.region and info["launched"] >= oldest]
        # with no servers yet, still make one call: it proves the IAM policy allows reading usage
        return sum(self.sent_bytes(iid, start, now) for iid in ids) if ids else self.sent_bytes("i-none", start, now)

    def instances(self):
        r = self.ec2.describe_instances(Filters=[
            {"Name": "tag:app", "Values": [APP_TAG]},
            {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}])
        return [i for res in r["Reservations"] for i in res["Instances"]]

    def default_vpc_subnet(self):
        vpcs = self.ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"]
        if not vpcs:
            raise RuntimeError(f"No default VPC in {self.region}. Create one in the VPC console "
                               "(Your VPCs > Actions > Create default VPC).")
        vpc = vpcs[0]["VpcId"]
        subnets = self.ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc]},
                                                     {"Name": "default-for-az", "Values": ["true"]}])["Subnets"]
        return vpc, subnets[0]["SubnetId"]

    def security_group(self, vpc):
        r = self.ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [SG_NAME]},
                                                       {"Name": "vpc-id", "Values": [vpc]}])
        if r["SecurityGroups"]:
            return r["SecurityGroups"][0]["GroupId"]
        self.log(f"Creating security group {SG_NAME} (no SSH)")
        return self.ec2.create_security_group(
            GroupName=SG_NAME, VpcId=vpc, Description="Shadowsocks proxy, no SSH",
            TagSpecifications=[{"ResourceType": "security-group",
                                "Tags": [{"Key": "app", "Value": APP_TAG}]}])["GroupId"]

    def allow_only(self, sg, ips):
        """Replace all inbound rules with TCP+UDP PORT from exactly these IPs (/32 each)."""
        ips = sorted(ips)
        old = self.ec2.describe_security_groups(GroupIds=[sg])["SecurityGroups"][0]["IpPermissions"]
        current = {(r["IpProtocol"], tuple(sorted(x["CidrIp"] for x in r.get("IpRanges", [])))) for r in old
                   if not r.get("Ipv6Ranges") and not r.get("UserIdGroupPairs") and not r.get("PrefixListIds")}
        wanted = {(p, tuple(f"{ip}/32" for ip in ips)) for p in ("tcp", "udp")}
        if current == wanted and len(old) == 2:
            return
        if old:
            self.ec2.revoke_security_group_ingress(GroupId=sg, IpPermissions=old)
        self.ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
            {"IpProtocol": p, "FromPort": PORT, "ToPort": PORT,
             "IpRanges": [{"CidrIp": f"{ip}/32", "Description": "my network, set by proxy app"} for ip in ips]}
            for p in ("tcp", "udp")])
        self.log(f"Inbound {PORT} now allowed only from your network: {', '.join(ips)}")

    def launch(self, password, sg, subnet, max_hours=MAX_HOURS, cap_bytes=0):
        ami = self.ssm.get_parameter(Name=AMI_PARAM)["Parameter"]["Value"]
        max_hours = clamp_hours(max_hours)
        tags = [{"Key": "Name", "Value": "ss-proxy"}, {"Key": "app", "Value": APP_TAG},
                {"Key": "auto-delete-hours", "Value": str(max_hours)}]  # read back for the countdown
        args = dict(
            ImageId=ami, InstanceType=INSTANCE_TYPE, MinCount=1, MaxCount=1,
            UserData=user_data(password, max_hours, cap_bytes),
            InstanceInitiatedShutdownBehavior="terminate",   # a shutdown from inside also stops billing
            MetadataOptions={"HttpTokens": "required"},
            NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": subnet, "Groups": [sg],
                                "AssociatePublicIpAddress": True, "DeleteOnTermination": True}],
            TagSpecifications=[{"ResourceType": t, "Tags": tags} for t in ("instance", "volume")])
        if self.ssm_role:  # optional: lets you open a shell with Session Manager
            args["IamInstanceProfile"] = {"Name": self.ssm_role}
        self.log(f"Launching {INSTANCE_TYPE} in {self.region}")
        iid = self.ec2.run_instances(**args)["Instances"][0]["InstanceId"]
        self.log(f"Instance {iid} starting")
        return iid  # returned before waiting, so the caller can clean up if anything after this fails

    def wait_running(self, iid):
        self.ec2.get_waiter("instance_running").wait(InstanceIds=[iid])
        return self.ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]

    def terminate(self, ids):
        self.log(f"Terminating {', '.join(ids)}")
        self.ec2.terminate_instances(InstanceIds=ids)
        self.ec2.get_waiter("instance_terminated").wait(InstanceIds=ids)

    def leftovers(self):
        """Everything tagged by this app that could still bill: instances and disks."""
        vols = self.ec2.describe_volumes(Filters=[
            {"Name": "tag:app", "Values": [APP_TAG]},
            {"Name": "status", "Values": ["creating", "available", "in-use"]}])["Volumes"]
        return [i["InstanceId"] for i in self.instances()] + [v["VolumeId"] for v in vols]

    def terminate_all(self):
        """Terminate every app server, then re-check. Returns whatever still exists (should be [])."""
        ids = [i["InstanceId"] for i in self.instances()]
        if ids:
            self.terminate(ids)
        else:
            self.log("No proxy servers are running")
        return self.leftovers()


# ---------- monthly data allowance ----------
# AWS's first 100 GB a month of data out to the internet is free (all your AWS use together). GB here is
# 10^9 bytes; AWS bills by 2^30-byte GB, so stopping at 99.99 leaves about 7 GB of slack for
# measurement delay and other AWS use.
FREE_DATA_BYTES = 100 * 10**9
CAP_BYTES = int(99.99 * 10**9)
WARN_AT = (0.80, 0.95)  # warn the owner once a month at these shares of the free 100 GB


def month_start(now):
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def load_ledger(path=None):
    """This app's servers ({id: {region, launched}}) and which warnings were shown, per month."""
    try:
        with open(path or USAGE_FILE, encoding="utf-8") as f:
            ledger = json.load(f)
    except (OSError, ValueError):
        ledger = {}
    return {"instances": ledger.get("instances", {}), "warned": ledger.get("warned", {})}


def save_ledger(ledger, path=None):
    os.makedirs(APP_DIR, exist_ok=True)
    write_json(path or USAGE_FILE, ledger)


def record_instance(iid, region, path=None, now=None):
    now = now or datetime.now(timezone.utc)
    ledger = load_ledger(path)
    keep_after = (now - timedelta(days=70)).isoformat()  # CloudWatch keeps hourly data for 63 days
    ledger["instances"] = {k: v for k, v in ledger["instances"].items() if v["launched"] >= keep_after}
    ledger["instances"][iid] = {"region": region, "launched": now.isoformat()}
    save_ledger(ledger, path)


def gb(n_bytes):
    return f"{n_bytes / 10**9:.1f} GB"


def data_text(used, allow_over):
    if used is None:
        return ("Data this month: unknown. Your IAM policy needs updating: AWS settings > Copy role permissions "
                "(or Copy user policy without MFA), and replace proxy-on-demand-ec2 with it.")
    text = f"Data this month: {gb(used)} of the free 100 GB"
    return text + (" (going over is allowed in AWS settings)" if allow_over else
                   f", {gb(max(0, CAP_BYTES - used))} left before the server stops itself")


def poll_seconds(used, allow_over):
    """How often to refresh while a server runs: often near the limit, rarely far from it. CloudWatch
    only updates every 5 minutes, so faster than that shows nothing new (the server itself enforces
    the limit every 5 seconds either way)."""
    if used is not None and not allow_over and CAP_BYTES - used < 10 * 10**9:
        return 300
    return 900


def due_warnings(used, warned_this_month):
    """Thresholds just crossed that haven't been shown this month."""
    return [t for t in WARN_AT if used is not None and used >= t * FREE_DATA_BYTES and t not in warned_this_month]


def server_hours(instance):
    """The auto-delete time a server was launched with (from its tag; older servers used the default)."""
    tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
    return clamp_hours(tags.get("auto-delete-hours", MAX_HOURS))


def money(usd):
    return f"${usd:.2f}" if usd >= 0.01 else "less than $0.01"


def cost_text(max_hours):
    """What a session costs, before you start it."""
    return (f"Applies to the next server you start. A server costs about ${HOURLY_USD:.3f} per hour, so at "
            f"most about {money(max_hours * HOURLY_USD)} if it runs the full {max_hours} h. "
            "Downloads beyond 100 GB a month cost extra.")


def uptime_text(launch_time, max_hours=MAX_HOURS, now=None):
    """'Running 1h05m · cost so far ~$0.02 (at most ~$0.22) · auto-deletes in 10h55m'."""
    h = ((now or datetime.now(timezone.utc)) - launch_time).total_seconds() / 3600
    left = max(0.0, max_hours - h)
    fmt = lambda x: f"{int(x)}h{int(x * 60) % 60:02d}m"
    return (f"Running {fmt(h)} · cost so far ~{money(h * HOURLY_USD)} "
            f"(at most ~{money(max_hours * HOURLY_USD)}) · auto-deletes in {fmt(left)}")


def wait_port(ip, log, recheck=lambda: None, timeout=300):
    """Wait until the server accepts connections. recheck() runs every 30 s, e.g. to allow
    public IPs of your network that were not seen at first."""
    log(f"Waiting for Shadowsocks on {ip}:{PORT} (first boot installs it, usually under 1 min)")
    end, next_check = time.time() + timeout, time.time() + 30
    while time.time() < end:
        try:
            socket.create_connection((ip, PORT), 3).close()
            return
        except OSError:
            if time.time() >= next_check:
                recheck()
                next_check = time.time() + 30
            time.sleep(5)
    raise RuntimeError(
        f"{ip}:{PORT} did not open in {timeout // 60} min. Usually your network reaches the internet "
        "through a public IP the app could not detect, so the server's firewall blocked you; your network "
        "may also block this traffic. To check the server itself: EC2 > instance > Actions > Monitor and "
        "troubleshoot > Get system log, and look for SS-SETUP-DONE (set KEEP_FAILED_SERVER = True to keep it).")


# ---------- UI ----------

# (key, what the user sees, typical seconds). The estimates come from real runs; the bar never lies by
# finishing early: a step that runs long holds at 95% of its share and the label says so.
START_STEPS = [("signin", "Signing in to AWS", 3), ("network", "Checking your network", 7),
               ("firewall", "Updating the server firewall", 4), ("launch", "Launching the server", 20),
               ("boot", "Server is installing Shadowsocks", 35), ("tunnel", "Starting the secure tunnel", 8),
               ("verify", "Checking the connection", 4)]
STOP_STEPS = [("disconnect", "Disconnecting", 3), ("signin", "Signing in to AWS", 3),
              ("delete", "Deleting the server and checking nothing is left", 40)]
REFRESH_STEPS = [("signin", "Signing in to AWS", 3), ("check", "Checking for running servers", 3)]
COLORS = {"idle": "#9aa0a6", "busy": "#f29900", "ok": "#188038", "warn": "#e8710a", "error": "#d93025"}
THEME = {"bg": "#f3f4f6", "card": "#ffffff", "line": "#e1e3e8", "text": "#1f2328", "muted": "#5f6368",
         "accent": "#1a73e8", "accent_hover": "#1765cc", "accent_off": "#a8c7fa"}


def scaler(root):
    """px(n): n pixels at 100 % Windows scaling, converted for this screen. Fonts are in points and
    scale by themselves; this keeps spacing in step with them on 1080p, 1440p and 4K alike."""
    k = root.winfo_fpixels("1i") / 96
    return lambda n: max(1, round(n * k))


def style_app(root, px):
    """One flat light theme built on Tk's own 'clam' (no extra library in the exe)."""
    t = THEME
    root.configure(bg=t["bg"])
    for name in ("TkDefaultFont", "TkTextFont"):  # not option_add("*Font"): that would override ttk style fonts
        tkfont.nametofont(name).configure(family="Segoe UI", size=11)
    for pattern, value in (("*Background", t["bg"]), ("*Entry.Background", "white"), ("*Foreground", t["text"])):
        root.option_add(pattern, value)  # also styles the AWS settings dialog
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".", background=t["bg"], foreground=t["text"], font=("Segoe UI", 11), bordercolor=t["line"],
                lightcolor=t["card"], darkcolor=t["line"], focuscolor=t["accent"])
    s.configure("Card.TFrame", background=t["card"])
    s.configure("Card.TLabel", background=t["card"])
    s.configure("Muted.Card.TLabel", background=t["card"], foreground=t["muted"])
    s.configure("Head.Card.TLabel", background=t["card"], font=("Segoe UI", 16, "bold"))
    s.configure("Title.Card.TLabel", background=t["card"], font=("Segoe UI", 11, "bold"))
    s.configure("TButton", background=t["card"], padding=(px(16), px(8)), relief="flat")
    s.map("TButton", background=[("disabled", t["bg"]), ("active", "#eceef1")],
          foreground=[("disabled", "#9aa0a6")])
    s.configure("Accent.TButton", background=t["accent"], foreground="white", bordercolor=t["accent"],
                lightcolor=t["accent"], darkcolor=t["accent"], font=("Segoe UI", 11, "bold"), padding=(px(26), px(8)))
    s.map("Accent.TButton", background=[("disabled", t["accent_off"]), ("active", t["accent_hover"])],
          foreground=[("disabled", "white")])
    s.configure("Horizontal.TProgressbar", background=t["accent"], troughcolor="#e8eaed", bordercolor="#e8eaed",
                lightcolor=t["accent"], darkcolor=t["accent"], thickness=px(10))
    s.configure("TSpinbox", fieldbackground="white", arrowsize=px(11), padding=px(3))


def card(parent, px):
    """A white panel with a hairline border."""
    return tk.Frame(parent, bg=THEME["card"], highlightthickness=1, highlightbackground=THEME["line"],
                    padx=px(20), pady=px(18))


def fit_to_screen(root, px):
    """Size the window to its content (never more than 90 % of the screen) and centre it."""
    root.update_idletasks()
    w = min(root.winfo_reqwidth(), int(root.winfo_screenwidth() * 0.9))
    h = min(root.winfo_reqheight(), int(root.winfo_screenheight() * 0.85))
    root.minsize(min(w, px(560)), min(h, px(300)))
    root.geometry(f"+{(root.winfo_screenwidth() - w) // 2}+{max(0, (root.winfo_screenheight() - h) // 3)}")


def progress_estimate(steps, index, elapsed):
    """(fraction done 0..1, seconds left, running late?) while step `index` has run for `elapsed` s."""
    expected = steps[index][2]
    current = min(elapsed, expected * 0.95)
    done = sum(s[2] for s in steps[:index]) + current
    total = sum(s[2] for s in steps)
    left = total - done
    return done / total, max(1, round(left)), elapsed > expected


def duration_text(seconds):
    return f"{seconds} s" if seconds < 60 else f"{seconds // 60} min {seconds % 60:02d} s"


class App:
    def __init__(self, root):
        self.root, self.q, self.busy, self.warp_was_on = root, queue.Queue(), False, False
        self.server_up, self.first_check = False, True
        self.session, self.session_expiry = None, None  # temporary AWS credentials, memory only
        self.connected_ip, self.health_failures, self.data_used = None, 0, None
        self.steps, self.step_index, self.step_started = None, 0, 0.0
        os.makedirs(APP_DIR, exist_ok=True)
        moved = migrate_old_files()

        root.title(f"Proxy on demand {__version__}")
        px = self.px = scaler(root)  # every size below is in "100 % scaling" pixels, scaled to this screen
        style_app(root, px)

        outer = ttk.Frame(root, padding=px(22))
        outer.pack(fill="both", expand=True)

        # status card: colored dot, headline, detail, and the progress bar while something runs
        status = card(outer, px)
        status.pack(fill="x")
        self.dot = tk.Label(status, text="●", font=("Segoe UI", 22), fg=COLORS["idle"], bg=THEME["card"])
        self.dot.grid(row=0, column=0, sticky="n", padx=(0, px(10)))
        self.status, self.detail = tk.StringVar(value="Checking..."), tk.StringVar()
        ttk.Label(status, textvariable=self.status, style="Head.Card.TLabel").grid(row=0, column=1, sticky="w")
        ttk.Label(status, textvariable=self.detail, style="Muted.Card.TLabel", justify="left",
                  wraplength=px(640)).grid(row=1, column=1, sticky="w", pady=(px(4), 0))
        status.columnconfigure(1, weight=1)
        self.progress = ttk.Frame(status, style="Card.TFrame")  # gridded by run(), hidden by "done"
        self.bar = ttk.Progressbar(self.progress, mode="determinate", maximum=1000)
        self.bar.pack(fill="x")
        self.step_text = tk.StringVar()
        ttk.Label(self.progress, textvariable=self.step_text, style="Muted.Card.TLabel").pack(anchor="w", pady=(px(6), 0))

        # buttons
        self.controls = ttk.Frame(outer)
        self.controls.pack(fill="x", pady=px(16))
        self.start_btn = ttk.Button(self.controls, text="Start", style="Accent.TButton", command=self.start)
        self.stop_btn = ttk.Button(self.controls, text="Stop", command=self.stop)
        self.buttons = [self.start_btn, self.stop_btn,
                        ttk.Button(self.controls, text="Refresh", command=self.refresh),
                        ttk.Button(self.controls, text="AWS settings", command=self.settings_dialog)]
        for b in self.buttons:
            b.pack(side="left", padx=(0, px(8)))
        self.activity_btn = ttk.Button(self.controls, text="Show activity", command=self.toggle_activity)
        self.activity_btn.pack(side="right")
        ttk.Button(self.controls, text="Logs", command=lambda: os.startfile(APP_DIR)).pack(side="right", padx=px(8))

        # server lifetime and cost, chosen before Start
        life = card(outer, px)
        life.pack(fill="x")
        ttk.Label(life, text="Server lifetime", style="Title.Card.TLabel").pack(anchor="w")
        row = ttk.Frame(life, style="Card.TFrame")
        row.pack(fill="x", pady=(px(8), 0))
        ttk.Label(row, text="Delete the server automatically after", style="Card.TLabel").pack(side="left")
        self.hours = tk.StringVar(value=str(load_settings()["max_hours"]))
        spin = ttk.Spinbox(row, from_=1, to=MAX_HOURS_LIMIT, width=4, textvariable=self.hours,
                           command=self.save_hours, justify="center")
        spin.pack(side="left", padx=px(8))
        spin.bind("<FocusOut>", lambda e: self.save_hours())
        spin.bind("<Return>", lambda e: self.save_hours())
        ttk.Label(row, text="hours, even if you never press Stop.", style="Card.TLabel").pack(side="left")
        self.cost = tk.StringVar(value=cost_text(clamp_hours(self.hours.get())))
        ttk.Label(life, textvariable=self.cost, style="Muted.Card.TLabel", wraplength=px(680),
                  justify="left").pack(anchor="w", pady=(px(8), 0))
        self.hours.trace_add("write", lambda *a: self.cost.set(cost_text(clamp_hours(self.hours.get()))))

        # activity log, folded away until asked for
        self.activity = card(outer, px)
        self.out = scrolledtext.ScrolledText(self.activity, height=9, font=("Consolas", 10), state="disabled",
                                             relief="flat", borderwidth=0, bg=THEME["card"])
        self.out.pack(fill="both", expand=True)
        fit_to_screen(root, px)

        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(200, self.pump)
        root.after(300_000, self.tick)  # then poll_seconds() decides
        root.after(60_000, self.health)
        if moved:
            self.log(f"Moved your saved {' and '.join(moved)} to {APP_DIR}")
        threading.Thread(target=self.check_for_update, daemon=True).start()
        self.refresh()

    def check_for_update(self):
        tag = newer_release()
        if tag:
            self.log(f"A new version ({tag}) is available: https://github.com/{REPO}/releases/latest")
            self.q.put(("title", f"Proxy on demand {__version__}  -  update available: {tag}"))

    def toggle_activity(self):
        if self.activity.winfo_ismapped():
            self.activity.pack_forget()
            self.activity_btn.config(text="Show activity")
        else:
            self.activity.pack(fill="both", expand=True, pady=(self.px(14), 0))
            self.activity_btn.config(text="Hide activity")
        self.root.geometry("")  # let the window grow or shrink to its content

    def save_hours(self):
        hours = clamp_hours(self.hours.get())
        self.hours.set(str(hours))
        if hours != load_settings()["max_hours"]:
            save_settings({"max_hours": hours})
            self.log(f"New servers will delete themselves after {hours} h")

    def step(self, key):
        """Called from the worker thread: the job moved on to step `key`."""
        self.q.put(("step", key))

    def animate(self):
        if not self.busy or not self.steps:
            return
        frac, left, late = progress_estimate(self.steps, self.step_index, time.time() - self.step_started)
        self.bar["value"] = int(frac * 1000)
        label = self.steps[self.step_index][1]
        n = f"step {self.step_index + 1} of {len(self.steps)}"
        self.step_text.set(f"{label}...  ({n}, taking a little longer than usual)" if late else
                           f"{label}...  ({n}, about {duration_text(left)} left)")
        self.root.after(250, self.animate)

    def log(self, msg):
        self.q.put(("log", time.strftime("%H:%M:%S ") + msg))
        try:
            with open(APP_LOG, "a", encoding="utf-8") as f:
                f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\n")
        except OSError:
            pass  # the on-screen log still works

    def set_status(self, msg, tone="idle", detail=""):
        self.q.put(("status", (msg, tone, detail)))

    def pump(self):
        while not self.q.empty():
            kind, msg = self.q.get()
            if kind == "status":
                headline, tone, detail = msg
                self.status.set(headline)
                self.detail.set(detail)
                self.dot.config(fg=COLORS[tone])
            elif kind == "step":
                keys = [s[0] for s in self.steps or []]
                if msg in keys:
                    self.step_index, self.step_started = keys.index(msg), time.time()
            elif kind == "start_label":
                self.start_btn.config(text=msg)
            elif kind == "title":
                self.root.title(msg)
            elif kind == "popup":
                messagebox.showinfo("Proxy on demand", msg)
            elif kind == "warn":
                messagebox.showwarning("Proxy on demand", msg)
            elif kind == "setup":
                self.root.after(100, self.settings_dialog)  # after "done" re-enables the buttons
            elif kind == "mfa":
                done, box = msg
                box["code"] = simpledialog.askstring(
                    "Sign in to AWS", "Enter the 6-digit code from your authenticator app:", parent=self.root)
                done.set()
            elif kind == "done":
                self.busy, self.steps = False, None
                self.progress.grid_remove()
                for b in self.buttons:
                    b.config(state="normal")
            else:
                self.out.config(state="normal")
                self.out.insert("end", msg + "\n")
                self.out.see("end")
                self.out.config(state="disabled")
        self.root.after(200, self.pump)

    def run(self, job, steps, headline):
        if self.busy:
            return
        self.busy = True
        for b in self.buttons:
            b.config(state="disabled")
        self.steps, self.step_index, self.step_started = steps, 0, time.time()
        self.bar["value"] = 0
        self.progress.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(self.px(14), 0))
        self.status.set(headline)
        self.detail.set("")
        self.dot.config(fg=COLORS["busy"])
        self.animate()

        def wrapped():
            try:
                job()
            except NoKeyError as e:
                self.log(str(e))
                self.set_status("Set up your AWS key to begin", "warn", "AWS settings has opened.")
                self.q.put(("setup", ""))
            except SignInCancelled as e:
                self.log(str(e))
                self.set_status("Signed out", "warn", "Press Refresh to sign in with your MFA code.")
            except Exception as e:  # show every failure instead of dying silently
                self.log(f"ERROR: {e}")
                self.set_status("Something went wrong", "error", "See the message and the activity log below.")
                self.q.put(("warn", f"{e}\n\nFull log: {APP_LOG}"))
            finally:
                self.q.put(("done", ""))
        threading.Thread(target=wrapped, daemon=True).start()

    def usage(self, aws, insts=()):
        """This month's data in bytes, or None if AWS won't say (old IAM policy without CloudWatch read).
        Running servers the ledger doesn't know (started by an older version) are added, so they count."""
        known = load_ledger()["instances"]
        for i in insts:
            if i["InstanceId"] not in known:
                record_instance(i["InstanceId"], aws.region, now=i["LaunchTime"])
        try:
            return aws.month_usage(load_ledger())
        except Exception as e:
            self.log(f"Could not read data usage from CloudWatch: {e}")
            return None

    def data_warnings(self, used, allow_over, server_gone):
        """Pop up each warning once a month: 80 %, 95 %, and when the server stopped itself at the limit."""
        ledger = load_ledger()
        month = datetime.now(timezone.utc).strftime("%Y-%m")
        warned = ledger["warned"].get(month, [])
        new = due_warnings(used, warned)
        capped = (server_gone and not allow_over and used is not None and used >= CAP_BYTES - 50 * 10**6
                  and "cap" not in warned)
        for t in new:
            self.q.put(("warn", (
                f"You have used {gb(used)} of this month's free 100 GB of data ({int(t * 100)} %).\n\n"
                + ("Going over is allowed in AWS settings, so your server keeps running. Data beyond 100 GB costs "
                   "about $0.09-0.11 per GB." if allow_over else
                   f"When it reaches 99.99 GB your server stops itself, so you are not charged for data. You have "
                   f"{gb(max(0, CAP_BYTES - used))} left.")
                + "\n\nThe free 100 GB resets on the 1st of each month (UTC). It is shared with anything else on "
                  "your AWS account that sends data to the internet.")))
        if capped:
            self.q.put(("warn", "Your server stopped itself: this month's free 100 GB of data is used up.\n\n"
                                "This keeps you from being charged for data. You can start again on the 1st of next "
                                "month (UTC), or tick \"Allow going over the free 100 GB\" in AWS settings if you "
                                "accept paying about $0.09-0.11 per GB beyond it."))
        if new or capped:
            ledger["warned"][month] = warned + new + (["cap"] if capped else [])
            save_ledger(ledger)
        return capped

    def report(self, aws):
        insts = aws.instances()
        tunnel = singbox_running()
        self.server_up = bool(insts)
        allow_over = load_settings()["allow_over"]
        self.data_used = self.usage(aws, insts)
        data = data_text(self.data_used, allow_over)
        capped = self.data_warnings(self.data_used, allow_over, server_gone=not insts)
        if insts:
            i = insts[0]
            up = uptime_text(i["LaunchTime"], server_hours(i)) + "\n" + data
            ip = i.get("PublicIpAddress", "no IP yet")
            if tunnel and not self.connected_ip:  # app was closed while connected: pick the connection up
                try:
                    if egress_ip() == ip:
                        self.connected_ip, self.health_failures = ip, 0
                        self.log(f"Picked up your existing connection through {ip}")
                except OSError:
                    pass
            if tunnel and self.connected_ip:
                self.set_status(f"Connected via {ip}", "ok",
                                f"{up}.\nChanged network (e.g. Wi-Fi to mobile data)? Press Reconnect.")
            else:
                self.set_status("Server running, but this laptop is not connected", "warn",
                                f"{up}.\nPress Reconnect to use it, or Stop to delete it.")
            if self.first_check:  # e.g. the app crashed or was closed with "leave it running"
                self.q.put(("warn", f"A proxy server is already running and billing ({up}).\n\n"
                                    "Press Reconnect to use it, or Stop if you are not using it."))
        elif tunnel:  # e.g. the server auto-deleted while the app was closed: this tunnel only blocks traffic
            stop_singbox()
            self.connected_ip = None
            self.log("The tunnel was still running but its server is gone (it probably auto-deleted), "
                     "so the tunnel was stopped to restore your normal internet.")
            self.set_status("Not connected", "idle", "Your server had been deleted, so the leftover tunnel "
                            "was stopped. Nothing is billing.\n" + data)
        else:
            self.connected_ip = None
            self.set_status("Not connected", "idle", "Nothing is running on AWS, so nothing is billing.\n" + data)
        if capped:
            self.set_status("Stopped: this month's free 100 GB of data is used up", "warn",
                            "Your server stopped itself so you aren't charged for data. Start works again on the 1st "
                            "(UTC), or allow going over in AWS settings.\n" + data)
        self.q.put(("start_label", "Reconnect" if insts else "Start"))
        self.first_check = False

    def refresh(self):
        def job():
            self.step("signin")
            aws = self.aws()
            self.step("check")
            self.report(aws)
        self.run(job, REFRESH_STEPS, "Checking...")

    def health(self):
        """While connected, check every minute that traffic still flows through the server."""
        def check():
            try:
                ok = egress_ip() == self.connected_ip
            except OSError:
                ok = False
            self.health_failures = 0 if ok else self.health_failures + 1
            if self.health_failures == 2:  # two misses in a row: tell the user once
                self.log("Connection check failed twice: the tunnel is not working. Press Reconnect.")
                self.set_status("Connection lost", "error", "Your network probably changed. Press Reconnect "
                                "(it reuses the server and just updates the allowed IPs), or Stop.")
        if self.connected_ip and not self.busy:
            threading.Thread(target=check, daemon=True).start()
        self.root.after(60_000, self.health)

    def session_valid(self):
        if self.session is None:
            return False
        return self.session_expiry is None or \
            (self.session_expiry - datetime.now(timezone.utc)).total_seconds() > 300  # None: no-MFA key

    def ask_mfa(self):
        """Called from the worker thread: ask the UI thread for an MFA code and wait for the answer."""
        done, box = threading.Event(), {}
        self.q.put(("mfa", (done, box)))
        done.wait()
        return box.get("code")

    def aws(self):
        settings = load_settings()
        if not self.session_valid():
            record = load_key()
            if not record:
                raise NoKeyError("No AWS key saved yet. Open AWS settings.")
            if not settings["mfa"]:
                self.session, self.session_expiry = key_session(record), None
                return Aws(self.log, settings, self.session)
            if "role_arn" not in record:
                raise NoKeyError("MFA is turned on, but the saved key was set up without it. "
                                 "Open AWS settings and save again.")
            code = self.ask_mfa()
            if code is None:
                raise SignInCancelled("Not signed in. Press Refresh or Start to sign in with your MFA code.")
            self.session, self.session_expiry = assume(record, code.strip(), settings["region"])
            self.log(f"Signed in with MFA until {self.session_expiry.astimezone():%H:%M} (credentials kept in memory only)")
        return Aws(self.log, settings, self.session)

    def settings_dialog(self):
        if self.busy:
            return
        s = load_settings()
        w = tk.Toplevel(self.root)
        w.title("AWS settings")
        w.transient(self.root)
        w.grab_set()
        w.resizable(False, False)
        mfa = tk.BooleanVar(value=s["mfa"])
        tk.Checkbutton(w, text="Require MFA (recommended)", variable=mfa, font=("Segoe UI", 10, "bold"),
                       command=lambda: update_mode()).grid(row=0, column=0, columnspan=2, sticky="w", padx=6, pady=(10, 0))
        mode_note = tk.Label(w, fg="gray", justify="left", anchor="w")
        mode_note.grid(row=1, column=0, columnspan=2, sticky="w", padx=26, pady=(0, 8))
        fields = {}
        rows = (("Region", "region", s["region"], ""),
                ("Session Manager role (optional)", "ssm_role", s["ssm_role"], ""),
                ("Access key ID", "key_id", "", ""),
                ("Secret access key", "secret", "", "•"))
        for r, (label, key, value, show) in enumerate(rows, start=2):
            tk.Label(w, text=label, anchor="w").grid(row=r, column=0, sticky="w", padx=10, pady=4)
            e = tk.Entry(w, width=46, show=show)
            e.insert(0, value)
            e.grid(row=r, column=1, padx=10, pady=4)
            fields[key] = e
        tk.Label(w, fg="gray", justify="left", text=(
            "Leave both key fields empty to keep the key already saved.\n"
            "The key is stored encrypted for your Windows account and is never shown again.")
        ).grid(row=6, column=0, columnspan=2, sticky="w", padx=10)
        over = tk.BooleanVar(value=s["allow_over"])
        tk.Checkbutton(w, text="Allow going over the free 100 GB of data a month", variable=over
                       ).grid(row=7, column=0, columnspan=2, sticky="w", padx=6, pady=(12, 0))
        tk.Label(w, fg="gray", justify="left", text=(
            "Off (recommended): a server stops itself at 99.99 GB of data this month, so data never costs you\n"
            "anything; Start is blocked until the 1st. On: no data limit; beyond 100 GB you pay about $0.09-0.11 per GB.")
        ).grid(row=8, column=0, columnspan=2, sticky="w", padx=26)

        def region_ok():
            region = fields["region"].get().strip()
            if not valid_region(region):
                messagebox.showerror("AWS settings", "Enter a region code such as ap-south-1.", parent=w)
                return None
            return region

        def copy(text, title, where):
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo(title, "Copied to the clipboard.\n\n" + where, parent=w)

        def typed_or_saved_record():
            key_id, secret = fields["key_id"].get().strip(), fields["secret"].get().strip()
            if key_id or secret:
                w.config(cursor="watch")
                w.update()
                try:
                    return inspect_key(key_id, secret)[0]
                finally:
                    w.config(cursor="")
            return load_key()

        def copy_key_policy():
            if mfa.get():
                copy(json.dumps(key_policy(), indent=2), "User policy",
                     "IAM > Policies > Create policy > JSON: paste, name it proxy-on-demand-key, "
                     "and attach it to the proxy-on-demand user (README step 5).")
                return
            region = region_ok()
            if region:  # no MFA: the user itself holds the least-privilege EC2 permissions
                copy(json.dumps(iam_policy(region, fields["ssm_role"].get().strip()), indent=2), "User policy",
                     "IAM > Policies > Create policy > JSON: paste, name it proxy-on-demand-ec2, "
                     "and attach it to the proxy-on-demand user (README, setup without MFA).")

        def update_mode():
            on = mfa.get()
            mode_note.config(text=(
                "Your access key alone can do nothing: each sign-in also needs a code from your phone,\n"
                "and AWS access lasts 1 hour, in memory only. Best if your laptop could ever be compromised."
                if on else
                "The key itself holds the app's least-privilege permissions; no phone codes.\n"
                "Anyone who gets the key can start and delete the app's small servers (all other safeguards stay)."))
            for b in role_buttons:
                b.config(state="normal" if on else "disabled")

        def copy_role_permissions():
            region = region_ok()
            if region:
                copy(json.dumps(iam_policy(region, fields["ssm_role"].get().strip()), indent=2),
                     "Role permissions", "IAM > Policies > Create policy > JSON: paste and name it "
                     "proxy-on-demand-ec2 (README step 7).")

        def copy_trust_policy():
            try:
                record = typed_or_saved_record()
            except Exception as e:
                return messagebox.showerror("AWS settings", str(e), parent=w)
            if not record:
                return messagebox.showerror("AWS settings", "Enter the access key first: the trust policy "
                                            "names the user that owns it.", parent=w)
            copy(json.dumps(trust_policy(record["user_arn"]), indent=2), "Role trust policy",
                 f"IAM > Roles > Create role > Custom trust policy: paste, attach proxy-on-demand-ec2, "
                 f"and name the role {ROLE_NAME} (README step 7).")

        def save():
            region, role = region_ok(), fields["ssm_role"].get().strip()
            if not region:
                return
            if region != s["region"] and self.server_up:  # would orphan a billing server in the old region
                return messagebox.showerror("AWS settings", "Press Stop before changing the region, "
                                            "so the server in the current region is terminated.", parent=w)
            key_id, secret = fields["key_id"].get().strip(), fields["secret"].get().strip()
            saved = load_key()
            if not (key_id or secret) and saved and mfa.get() != s["mfa"]:
                key_id, secret = saved["key_id"], saved["secret"]  # MFA switched: re-check the saved key
            if key_id or secret:
                w.config(cursor="watch")
                w.update()
                try:
                    record, warnings = inspect_key(key_id, secret, mfa.get(), region)
                except Exception as e:
                    return messagebox.showerror("AWS settings", f"This key cannot be used:\n\n{e}", parent=w)
                finally:
                    w.config(cursor="")
                if warnings and not messagebox.askyesno(
                        "Key works, but...", "\n\n".join(warnings) + "\n\nSave this key anyway?", parent=w):
                    return
                save_key(record)
                self.log(f"AWS key saved, encrypted (user {record['user_arn'].split('/')[-1]})")
            save_settings({"mfa": mfa.get(), "region": region, "ssm_role": role, "allow_over": over.get()})
            self.session = None  # settings or key changed: sign in again
            w.destroy()
            self.refresh()  # signs in (with the MFA code if enabled) and proves the whole setup works

        bar = tk.Frame(w)
        bar.grid(row=9, column=0, columnspan=2, pady=(10, 4))
        tk.Button(bar, text="Copy user policy", command=copy_key_policy).pack(side="left", padx=4)
        role_buttons = [tk.Button(bar, text="Copy role trust policy", command=copy_trust_policy),
                        tk.Button(bar, text="Copy role permissions", command=copy_role_permissions)]
        for b in role_buttons:
            b.pack(side="left", padx=4)
        bar2 = tk.Frame(w)
        bar2.grid(row=10, column=0, columnspan=2, pady=(4, 10))
        tk.Button(bar2, text="Save and sign in", command=save).pack(side="left", padx=6)
        tk.Button(bar2, text="Cancel", command=w.destroy).pack(side="left", padx=6)
        update_mode()

    def start(self):
        self.save_hours()
        hours = load_settings()["max_hours"]

        def job():
            self.step("signin")
            aws = self.aws()
            if ensure_config():
                self.log(f"Created a new sing-box config with a random password at {SB_CONFIG}")
            password = ss_outbound(load_config()).get("password")
            if not password:
                raise RuntimeError(f"No Shadowsocks password in {SB_CONFIG} (outbound ss-out)")
            if warp_connected():
                self.log("Disconnecting Cloudflare WARP (two VPNs at once break the tunnel)")
                warp_disconnect()
                self.warp_was_on = True
            self.step("network")
            stop_singbox()  # so the IP check below sees your real IP, not the old server's
            self.connected_ip = None
            allowed = my_ips()
            self.step("firewall")
            vpc, subnet = aws.default_vpc_subnet()
            sg = aws.security_group(vpc)
            aws.allow_only(sg, allowed)

            def recheck():  # networks with several public IPs: allow any we had not seen yet
                new = my_ips(rounds=2) - allowed
                if new:
                    allowed.update(new)
                    aws.allow_only(sg, allowed)
            self.step("launch")
            insts = aws.instances()
            stopped = [i["InstanceId"] for i in insts if i["State"]["Name"] in ("stopping", "stopped")]
            if stopped:  # a stopped server still bills for its disk; never leave one behind
                aws.terminate(stopped)
            live = [i for i in insts if i["State"]["Name"] in ("pending", "running")]
            launched = None
            try:
                if live:
                    self.log(f"Reusing running server {live[0]['InstanceId']}")
                    inst = aws.wait_running(live[0]["InstanceId"])
                else:
                    cap = self.data_allowance(aws)
                    launched = aws.launch(password, sg, subnet, hours, cap)
                    record_instance(launched, aws.region)  # counted toward the month even if it fails later
                    inst = aws.wait_running(launched)
                ip = inst["PublicIpAddress"]
                self.step("boot")
                wait_port(ip, self.log, recheck)
                self.step("tunnel")
                stop_singbox()
                set_server(ip)
                self.log(f"sing-box config now points at {ip}")
                start_singbox(find_singbox() or install_singbox(self.log))
                self.step("verify")
                got = None
                for _ in range(6):
                    try:
                        got = egress_ip()
                        break
                    except OSError:
                        time.sleep(3)
                if got != ip:
                    raise RuntimeError(
                        f"No traffic got through the tunnel. See {SB_LOG}" if got is None else
                        f"Traffic left via {got}, not {ip}. Is another VPN on?")
            except Exception:
                stop_singbox()  # a dead tunnel would cut your internet
                if launched and not KEEP_FAILED_SERVER:
                    self.log("Start failed: terminating the new server so it does not keep billing")
                    try:
                        aws.terminate([launched])
                    except Exception as e:
                        self.log(f"WARNING: could not terminate {launched} ({e}). TERMINATE IT IN THE EC2 CONSOLE.")
                if self.warp_was_on:
                    warp("connect")
                    self.warp_was_on = False
                raise
            self.connected_ip, self.health_failures = got, 0
            self.log(f"Successfully connected. Your public IP is now {got}")
            self.report(aws)
            server_h = server_hours(inst)
            self.q.put(("popup", f"Successfully connected.\n\nYour traffic now leaves via {got} ({aws.region}).\n\n"
                                 f"Press Stop when you are done. Otherwise the server deletes itself after "
                                 f"{server_h} h (at most about {money(server_h * HOURLY_USD)}).\n\n"
                                 "Changed network (e.g. Wi-Fi to mobile data) and it stops working? "
                                 "Press Reconnect."))
        self.run(job, START_STEPS, "Reconnecting..." if self.server_up else "Starting...")

    def data_allowance(self, aws):
        """Bytes the new server may send before it stops itself (0 = no limit, the user allowed going over)."""
        if load_settings()["allow_over"]:
            self.log("No data limit on this server: going over the free 100 GB is allowed in AWS settings")
            return 0
        used = self.usage(aws)
        if used is None:
            raise RuntimeError(
                "The app can't read this month's data usage, so it can't guarantee the server stops before the free "
                "100 GB.\n\nUpdate your IAM policy: AWS settings > Copy role permissions (or Copy user policy if MFA "
                "is off), then in the AWS console replace the proxy-on-demand-ec2 policy's JSON with it. "
                "Or tick \"Allow going over the free 100 GB\" in AWS settings.")
        left = CAP_BYTES - int(used)
        if left < 200 * 10**6:
            raise RuntimeError(
                f"This month's free 100 GB of data is used up ({gb(used)} so far), so Start is blocked to keep you "
                "from being charged.\n\nIt resets on the 1st of next month (UTC). To start anyway, tick \"Allow going "
                "over the free 100 GB\" in AWS settings (data beyond it costs about $0.09-0.11 per GB).")
        self.log(f"This server may send {gb(left)} more this month; it stops itself at the limit")
        return left

    def stop(self):
        def job():
            self.step("disconnect")
            self.log("Stopping sing-box")
            stop_singbox()
            self.connected_ip = None
            self.step("signin")
            aws = self.aws()
            self.step("delete")
            left = aws.terminate_all()
            if self.warp_was_on:
                self.log("Reconnecting Cloudflare WARP")
                warp("connect")
                self.warp_was_on = False
            self.report(aws)
            if left:
                self.log(f"WARNING: still exists after Stop: {', '.join(left)}")
                self.q.put(("warn", f"These still exist and may bill:\n{', '.join(left)}\n\n"
                                    f"Press Stop again, or delete them in the EC2 console ({aws.region})."))
            else:
                self.log("Verified: no proxy servers or disks left. Nothing is billing.")
        self.run(job, STOP_STEPS, "Stopping...")

    def tick(self):
        """While a server exists, refresh uptime, cost and data: every 15 min, every 5 min near the data limit.
        (The limit itself is enforced by the server every 5 seconds, even with the app closed.)"""
        if self.server_up and not self.busy:
            if self.session_valid():  # never pop up an MFA prompt from a background timer
                self.refresh()
            else:
                self.set_status("Signed out (the 1-hour sign-in ended)", "warn",
                                "Your server may still be running and billing. Press Refresh to sign in "
                                "and check, or Stop to end it. Its data limit still applies.")
        self.root.after(poll_seconds(self.data_used, load_settings()["allow_over"]) * 1000, self.tick)

    def on_close(self):
        if self.busy:
            if not messagebox.askyesno("Busy", "An operation is still running. Close anyway?"):
                return
            self.root.destroy()
            return
        if not self.server_up and not singbox_running():
            self.root.destroy()
            return
        ans = messagebox.askyesnocancel("Quit", "Stop the proxy and delete the server before quitting?\n\n"
                                                "Yes = stop everything, nothing keeps billing.\n"
                                                "No = stay connected with the window closed. The server keeps "
                                                "billing until it deletes itself at the time you chose; open "
                                                "the app again any time to see it or press Stop.")
        if ans is None:
            return
        if ans:
            self.stop()
            self.root.after(500, self.close_when_idle)
        else:
            self.root.destroy()

    def close_when_idle(self):
        if self.busy:
            self.root.after(500, self.close_when_idle)
        else:
            self.root.destroy()


def version_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def newer_release():
    """The latest GitHub release tag if it is newer than this version, else None. Never raises."""
    try:
        req = urllib.request.Request(f"https://api.github.com/repos/{REPO}/releases/latest",
                                     headers={"User-Agent": "proxy-on-demand", "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            tag = json.load(r)["tag_name"]
        return tag if version_tuple(tag) > version_tuple(__version__) else None
    except Exception:
        return None  # offline, rate-limited, private repo: just skip the notice


def self_check():
    """`--check`: prove a build is complete without touching AWS or the network. Exit code 0 = OK."""
    import boto3  # bundled?
    boto3.session.Session().get_available_regions("ec2")  # botocore data files bundled?
    assert _dpapi(_dpapi(b"x", protect=True), protect=False) == b"x"
    assert "SS-SETUP-DONE" in user_data("x") and iam_policy("ap-south-1")["Statement"]
    root = tk.Tk()  # Tcl/Tk bundled?
    ttk.Progressbar(root)
    root.destroy()
    return 0


def ensure_admin():
    """sing-box needs admin rights to create its network adapter; relaunch elevated if needed.
    (The packaged .exe asks for admin rights through its manifest, so this is mostly for source runs.)"""
    if ctypes.windll.shell32.IsUserAnAdmin():
        return
    if getattr(sys, "frozen", False):
        exe, args = sys.executable, ""
    else:
        exe = sys.executable
        pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.exists(pyw):
            exe = pyw
        args = f'"{os.path.abspath(__file__)}"'
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args, None, 1)
    sys.exit(0 if rc > 32 else "Administrator rights are needed to run sing-box.")


def already_running():
    """One window at a time: two copies would fight over the same server and tunnel."""
    already_running.handle = ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\proxy-on-demand")
    return ctypes.windll.kernel32.GetLastError() == 183  # ERROR_ALREADY_EXISTS


if __name__ == "__main__":
    if "--version" in sys.argv:
        print(__version__)
        sys.exit(0)
    if "--check" in sys.argv:
        sys.exit(self_check())
    ensure_admin()
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # crisp text instead of Windows blurring a stretched window
    except (AttributeError, OSError):
        pass
    if already_running():
        messagebox.showinfo("Proxy on demand", "Proxy on demand is already open. Use the window that is open.")
        sys.exit(0)
    root = tk.Tk()
    App(root)
    root.mainloop()
