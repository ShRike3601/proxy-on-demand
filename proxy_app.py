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
import secrets
import urllib.parse
import urllib.request
import webbrowser
import zipfile
from datetime import datetime, timedelta, timezone
from tkinter import font as tkfont, messagebox, scrolledtext, simpledialog, ttk

__version__ = "1.4.0"
REPO = "ShRike3601/proxy-on-demand"  # GitHub repo, for the "new version available" notice
ROLE_NAME = "proxy-on-demand-role"  # IAM role holding the app's EC2 permissions; assumable only with MFA
SESSION_SECONDS = 3600              # temporary credentials last 1 hour, in memory only
OLD_PROFILE = "proxy-on-demand"     # plain-text profile used by earlier versions; removed on first save
APP_TAG = "ss-proxy-app"          # every resource we create is tagged app=ss-proxy-app
# Server sizes offered in Settings > Advanced. x86 only: the server installs the x86_64 Shadowsocks build.
# Prices: on-demand Linux, Mumbai (ap-south-1), approximate; other regions differ a little.
SERVER_SIZES = {
    "t3.micro": (0.0112, "Small: 1 GB memory. Plenty for 1-3 people (default)"),
    "t3.small": (0.0224, "Medium: 2 GB memory, about twice Small's steady network share. A few people"),
    "t3.medium": (0.0448, "Large: 4 GB memory, about four times Small's steady network share. A small group"),
}
INSTANCE_TYPE = "t3.micro"  # default size
EXTRA_USD = 0.006  # per hour on top of the server: public IPv4 address ($0.005) + 8 GB disk
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
DEFAULT_SETTINGS = {"mfa": False, "region": "ap-south-1", "ssm_role": "",  # MFA: opt-in extra security
                    "max_hours": 12, "allow_over": False,  # allow_over: let data go past the free 100 GB
                    "size": "t3.micro", "sharing": False, "sharing_agreed": False,
                    "joined": ""}  # joined: the friend's server this laptop is connected to, if any
KEY_FILE = os.path.join(APP_DIR, "aws-key.bin")  # DPAPI-encrypted, readable only by this Windows user
DPAPI_ENTROPY = b"proxy-on-demand/aws-key/v1"
PLAINTEXT_CRED_FILE = os.environ.get("AWS_SHARED_CREDENTIALS_FILE") or \
    os.path.join(os.path.expanduser("~"), ".aws", "credentials")
SB_DIR = SB_HOME = os.path.join(APP_DIR, "sing-box")  # sing-box.exe, its config and its log
SB_CONFIG = os.path.join(SB_DIR, "config.json")
SB_LOG = os.path.join(SB_DIR, "sing-box.log")
JOIN_CONFIG = os.path.join(SB_DIR, "join.json")  # used while connected to a friend's server
SB_VERSION = "1.14.4"
SB_ZIP_SHA256 = "99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df"  # official windows-amd64 zip
WARP_CLI = r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe"
MAX_HOURS = 12                    # default auto-delete time; users pick 1..MAX_HOURS_LIMIT on the main window
MAX_HOURS_LIMIT = 24
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
                       "method": METHOD, "password": password}, {"type": "direct", "tag": "direct"}],
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


def set_server(ip, path=SB_CONFIG, port=PORT, method=None, password=None):
    """Point the ss-out outbound at ip, keeping one backup of the original. Traffic to the server's own
    address goes direct (not into the tunnel), so the app can reach the server's status page from your network."""
    cfg = load_config(path)
    out = ss_outbound(cfg)
    out.update(server=ip, server_port=port, **({"method": method} if method else {}),
               **({"password": password} if password else {}))
    if not any(o.get("tag") == "direct" for o in cfg["outbounds"]):  # configs from before 1.3
        cfg["outbounds"].append({"type": "direct", "tag": "direct"})
    route = cfg.setdefault("route", {})
    route["rules"] = [r for r in route.get("rules", []) if r.get("outbound") != "direct"] +         [{"ip_cidr": [f"{ip}/32"], "outbound": "direct"}]
    backup = path + ".app-backup"
    if not os.path.exists(backup):
        shutil.copy2(path, backup)
    write_json(path, cfg)


def make_join_config(host, port, method, password, path=None):
    """A separate config for a friend's server, so your own server's password is never overwritten."""
    path = path or JOIN_CONFIG
    os.makedirs(os.path.dirname(path), exist_ok=True)
    write_json(path, default_config(password))
    set_server(host, path, port, method, password)
    return path


def share_link(host, password, port=PORT, method=METHOD, name="Proxy on demand"):
    """Standard Shadowsocks link (SIP002; 2022 keys are percent-encoded, not base64)."""
    q = lambda v: urllib.parse.quote(v, safe="")
    return f"ss://{q(method)}:{q(password)}@{host}:{port}#{q(name)}"


def parse_link(link):
    """(host, port, method, password) from an ss:// link; accepts plain and base64 user info. Raises ValueError."""
    link = link.strip()
    if not link.lower().startswith("ss://") or "@" not in link:
        raise ValueError("That isn't a share link. It should start with ss:// and contain an @.")
    u = urllib.parse.urlsplit(link)
    try:
        host, port = u.hostname, u.port
    except ValueError:
        host = port = None
    if not host or not port:
        raise ValueError("The link is missing the server address or port. Ask for the link again.")
    if u.password is not None:
        method, password = urllib.parse.unquote(u.username or ""), urllib.parse.unquote(u.password)
    else:  # older style: base64("method:password")
        raw = urllib.parse.unquote(u.username or "")
        try:
            method, _, password = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode().partition(":")
        except (ValueError, UnicodeDecodeError):
            raise ValueError("The link's password part can't be read. Ask for the link again.") from None
    if not method or not password:
        raise ValueError("The link has no password in it. Ask for the link again.")
    return host, port, method, password


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
    if s["size"] not in SERVER_SIZES:
        s["size"] = INSTANCE_TYPE
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
                           "Windows account?). Enter it again in Settings.") from e


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
                            "'Copy IAM policy' in Settings to this user (README, Quick Start step 5).")
        return record, warnings
    try:
        devices = s.client("iam").list_mfa_devices(UserName=user)["MFADevices"]
    except ClientError as e:
        raise RuntimeError("This key cannot look up its MFA device. Attach the key policy "
                           "(Settings > Copy IAM policy) to this user.") from e
    if not devices:
        raise RuntimeError(f"The user {user} has no MFA device. Add a virtual MFA device to it (README, step 6), "
                           "or untick 'Require MFA' in Settings.")
    record.update(mfa_serial=devices[0]["SerialNumber"], role_arn=f"arn:aws:iam::{account}:role/{ROLE_NAME}")
    return record, warnings


def key_policy():
    """For the IAM user that owns the stored key: it can only assume the app role and find its own MFA device."""
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "AssumeAppRoleOnly", "Effect": "Allow", "Action": "sts:AssumeRole",
         "Resource": f"arn:aws:iam::*:role/{ROLE_NAME}"},
        {"Sid": "FindOwnMfaDevice", "Effect": "Allow", "Action": "iam:ListMFADevices",
         "Resource": "arn:aws:iam::*:user/${aws:username}"}]}


POLICY_NAME, KEY_POLICY_NAME, USER_NAME = "proxy-on-demand-ec2", "proxy-on-demand-key", "proxy-on-demand"
MFA_GUIDE = "extra-security-with-mfa-optional"
# After each Copy button: (pop-up title, numbered steps with the exact names, README section anchor)
COPY_GUIDES = {
    "user": ("IAM policy copied", (
        f"1. IAM > Policies > Create policy > JSON tab. Replace everything with Ctrl+V.\n"
        f"2. Next. Policy name: {POLICY_NAME}  (exactly). Create policy.\n"
        f"3. IAM > Users > Create user. Name: {USER_NAME}. Leave console access off.\n"
        f"4. Permissions: Attach policies directly > tick {POLICY_NAME} > Create user.\n"
        f"5. Open the user > Security credentials > Create access key > Local code. Paste both keys here.\n\n"
        f"Updating an existing setup? Only replace the JSON of {POLICY_NAME} (Policies > {POLICY_NAME} > Edit)."),
        "step-5-create-the-apps-iam-user"),
    "mfa_user": ("User policy copied (MFA)", (
        f"1. IAM > Policies > Create policy > JSON tab. Replace everything with Ctrl+V.\n"
        f"2. Next. Policy name: {KEY_POLICY_NAME}  (exactly). Create policy.\n"
        f"3. IAM > Users > {USER_NAME} > Permissions: attach {KEY_POLICY_NAME}, remove {POLICY_NAME}."),
        MFA_GUIDE),
    "role_permissions": ("Role permissions copied", (
        f"1. IAM > Policies > {POLICY_NAME} > Edit > JSON (or Create policy > JSON if it doesn't exist).\n"
        f"2. Replace everything with Ctrl+V. Save (name it {POLICY_NAME} if new)."),
        MFA_GUIDE),
    "trust": ("Role trust policy copied", (
        f"1. IAM > Roles > Create role > Custom trust policy. Replace everything with Ctrl+V.\n"
        f"2. Next. Attach {POLICY_NAME}.\n"
        f"3. Role name: {ROLE_NAME}  (exactly). Create role."),
        MFA_GUIDE),
}


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
        {"Sid": "LaunchOnlyTaggedSmallServers", "Effect": "Allow", "Action": "ec2:RunInstances",
         "Resource": ec2 + "instance/*",
         "Condition": {"StringEquals": {"ec2:InstanceType": list(SERVER_SIZES), "aws:RequestTag/app": APP_TAG}}},
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


SHARING_HELP = """How sharing works

WHAT IT IS
Sharing lets people you trust use your server. They don't need an AWS account: they install Proxy on demand, press "Join a friend" and paste your link. (Any Shadowsocks app, such as sing-box, NekoBox or Shadowrocket, can use the link too.)

TURNING IT ON
Turn on the "Share my server" switch at the bottom of the main window. While it's on, your server accepts connections from any network; the key inside the link is the only lock. Turning it off closes the server to everyone but your own network again.

THE LINK
Press "Copy share link" and send it privately (not in public chats). It works only while your current server runs: after Stop, or when the server deletes itself, the next server gets a new address and a new link. Reconnect keeps the same server, so the link stays valid.

WHO IS CONNECTED
The bottom of the main window lists the devices connected right now, by IP address. Yours is marked "you". With one shared link, the server can't tell people apart by name. The limit is 5 devices at once, you included (two people on the same Wi-Fi count as one). If more connect, the app warns you: your link has probably been passed on, so press Stop and share a fresh link.

REMOVING PEOPLE
Everyone uses the same key, so you can't remove just one person. To cut everyone off at once, turn sharing off (takes effect within seconds), or press Stop: the next server has a new key and address. Then share a fresh link only with the people you still want.

WHAT IT COSTS YOU
You pay for everything on your server: its running time and all data. Everyone shares your free 100 GB a month; when it's used up, the server stops for everyone. Bigger groups may need a bigger server size (Settings > Server & data).

YOUR RESPONSIBILITY
Their traffic leaves through your server and your AWS account, so you are responsible for it under AWS's Acceptable Use Policy (aws.amazon.com/aup). Share only with people you trust, never for illegal, abusive or unfair purposes, and cut people off if they misuse it.

FOR PEOPLE WHO JOIN
The server's owner can see your IP address and which sites you visit (not the content of encrypted pages). Only join servers of people you trust. Press Stop to disconnect."""

JOIN_INFO = ("You're connected through someone else's server with a link they shared.\n"
             "- The owner can see your IP address and which sites you visit (not the content of encrypted pages). "
             "Only join servers of people you trust.\n"
             "- The owner pays for your usage and is responsible for it, so use it fairly and legally.\n"
             "- The link works only while the owner's server runs. If it stops, ask them for a fresh link.")

JOIN_WARNING = ("Paste the share link someone sent you. Before you connect:\n"
                "- Only join servers of people you trust. The owner can see your IP address and which sites you "
                "visit (not the content of encrypted pages).\n"
                "- The owner pays for your usage and is responsible for it, so use it fairly and legally.\n"
                "- Press Stop to disconnect. The link stops working when the owner's server stops.")

SHARE_REMINDER = ("Share link copied.\n\n"
                  "- Send it privately to people you trust. Anyone with it can use your server while it runs.\n"
                  "- They paste it in Proxy on demand > Join a friend (or any Shadowsocks app).\n"
                  "- You pay for their usage, and their traffic is your responsibility.\n"
                  "- They should know you can see their IP address and which sites they visit.")

AGREEMENT_POINTS = (
    "I'll share only with people I trust (up to 5 devices at once, me included), and never post the link publicly.",
    "I pay for everything they use: server time and data (it counts toward my free 100 GB a month).",
    "Their traffic leaves through my server and AWS account, so I'm responsible for it under AWS's Acceptable "
    "Use Policy. It must not be used for anything illegal, abusive or unfair.",
    "I'll cut off anyone who misuses it (turn sharing off or press Stop).",
)


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


def start_singbox(exe, config=None):
    os.makedirs(SB_DIR, exist_ok=True)
    log = open(SB_LOG, "w", encoding="utf-8")
    proc = subprocess.Popen([exe, "run", "-c", config or SB_CONFIG], stdout=log, stderr=subprocess.STDOUT,
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

SHARE_LIMIT = 5  # devices (networks) at once on one shared server, you included; shown and warned, not yet enforced
STATUS_PORT = 8443  # the server's connected-devices page; the firewall lets only the owner's network reach it
STATUS_SCRIPT = r"""cat > /usr/local/bin/ss-status.py <<'EOF'
# Tells the owner's app which IP addresses are connected right now. Answers only at /<token>.
import http.server, json, subprocess
TOKEN = "TOKEN_VALUE"
class Status(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/" + TOKEN:
            self.send_response(404)
            self.end_headers()
            return
        out = subprocess.run(["ss", "-Htn", "state", "established", "( sport = :PORT_VALUE )"],
                             capture_output=True, text=True).stdout
        peers = {}
        for line in out.splitlines():
            ip = line.split()[-1].rsplit(":", 1)[0].strip("[]").replace("::ffff:", "")
            peers[ip] = peers.get(ip, 0) + 1
        body = json.dumps(peers).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
http.server.HTTPServer(("0.0.0.0", STATUS_PORT_VALUE), Status).serve_forever()
EOF
cat > /etc/systemd/system/ss-status.service <<'EOF'
[Unit]
Description=Connected devices, for the owner's app
[Service]
DynamicUser=yes
ExecStart=/usr/bin/python3 /usr/local/bin/ss-status.py
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now ss-status
"""


def server_peers(ip, token, timeout=4):
    """{ip: connections} connected to the server right now, or None if the status page can't be reached."""
    if not token:
        return None
    try:
        with urllib.request.urlopen(f"http://{ip}:{STATUS_PORT}/{token}", timeout=timeout) as r:
            return {str(k): int(v) for k, v in json.load(r).items()}
    except (OSError, ValueError, AttributeError):
        return None


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


def user_data(password, max_hours=MAX_HOURS, cap_bytes=0, status_token=""):
    """First-boot script: install shadowsocks-rust (checksum-verified) and run it as a service.
    cap_bytes > 0: the server powers itself off after sending that many bytes (0 = no data cap)."""
    max_hours = clamp_hours(max_hours)
    cap = DATA_CAP_SCRIPT.replace("LIMIT", str(int(cap_bytes))) if cap_bytes > 0 else ""
    status = (STATUS_SCRIPT.replace("TOKEN_VALUE", status_token).replace("STATUS_PORT_VALUE", str(STATUS_PORT))
              .replace("PORT_VALUE", str(PORT))) if status_token else ""
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
{status}echo SS-SETUP-DONE
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

    def allow_only(self, sg, ips, sharing=False):
        """Replace all inbound rules: the proxy port (TCP+UDP) from your network's IPs, or from anywhere while
        sharing (the key is then the only lock); the status page always from your network only."""
        mine = [f"{ip}/32" for ip in sorted(ips)]
        main = ["0.0.0.0/0"] if sharing else mine
        want = [("tcp", PORT, main), ("udp", PORT, main), ("tcp", STATUS_PORT, mine)]
        old = self.ec2.describe_security_groups(GroupIds=[sg])["SecurityGroups"][0]["IpPermissions"]
        current = {(r["IpProtocol"], r.get("FromPort"), tuple(sorted(x["CidrIp"] for x in r.get("IpRanges", []))))
                   for r in old if not r.get("Ipv6Ranges") and not r.get("UserIdGroupPairs") and not r.get("PrefixListIds")}
        if current == {(p, port, tuple(sorted(c))) for p, port, c in want} and len(old) == len(want):
            return
        if old:
            self.ec2.revoke_security_group_ingress(GroupId=sg, IpPermissions=old)
        self.ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
            {"IpProtocol": p, "FromPort": port, "ToPort": port,
             "IpRanges": [{"CidrIp": c, "Description": "set by proxy app"} for c in cidrs]}
            for p, port, cidrs in want])
        self.log(f"Port {PORT} now open to everyone (sharing is on)" if sharing else
                 f"Port {PORT} now allowed only from your network: {', '.join(sorted(ips))}")

    def owner_ips(self, instance):
        """Your network's IPs, as recorded in the server's firewall (the status-page rule)."""
        try:
            sg = instance["SecurityGroups"][0]["GroupId"]
            perms = self.ec2.describe_security_groups(GroupIds=[sg])["SecurityGroups"][0]["IpPermissions"]
        except (KeyError, IndexError):
            return set()
        return {x["CidrIp"].split("/")[0] for r in perms if r.get("FromPort") == STATUS_PORT
                for x in r.get("IpRanges", [])}

    def launch(self, password, sg, subnet, max_hours=MAX_HOURS, cap_bytes=0, size=INSTANCE_TYPE):
        ami = self.ssm.get_parameter(Name=AMI_PARAM)["Parameter"]["Value"]
        max_hours = clamp_hours(max_hours)
        token = secrets.token_urlsafe(18)  # the status page answers only to this
        tags = [{"Key": "Name", "Value": "ss-proxy"}, {"Key": "app", "Value": APP_TAG},
                {"Key": "auto-delete-hours", "Value": str(max_hours)},  # read back for the countdown
                {"Key": "status-token", "Value": token}]
        args = dict(
            ImageId=ami, InstanceType=size if size in SERVER_SIZES else INSTANCE_TYPE, MinCount=1, MaxCount=1,
            UserData=user_data(password, max_hours, cap_bytes, token),
            InstanceInitiatedShutdownBehavior="terminate",   # a shutdown from inside also stops billing
            MetadataOptions={"HttpTokens": "required"},
            NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": subnet, "Groups": [sg],
                                "AssociatePublicIpAddress": True, "DeleteOnTermination": True}],
            TagSpecifications=[{"ResourceType": t, "Tags": tags} for t in ("instance", "volume")])
        if self.ssm_role:  # optional: lets you open a shell with Session Manager
            args["IamInstanceProfile"] = {"Name": self.ssm_role}
        self.log(f"Launching {args['InstanceType']} in {self.region}")
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
        return ("Data this month: unknown. Your IAM policy needs updating: Settings > Copy IAM policy "
                "(Copy role permissions with MFA), and replace proxy-on-demand-ec2's JSON with it.")
    text = f"Data this month: {gb(used)} of the free 100 GB"
    return text + (" (going over is allowed in Settings)" if allow_over else
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


def tag(instance, key, default=""):
    return {t["Key"]: t["Value"] for t in instance.get("Tags", [])}.get(key, default)


def server_hours(instance):
    """The auto-delete time a server was launched with (from its tag; older servers used the default)."""
    tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
    return clamp_hours(tags.get("auto-delete-hours", MAX_HOURS))


def money(usd):
    return f"${usd:.2f}" if usd >= 0.01 else "less than $0.01"


def hourly_usd(size=INSTANCE_TYPE):
    """Server + public IP + disk, per hour (approximate, Mumbai prices; data transfer not included)."""
    return SERVER_SIZES.get(size, SERVER_SIZES[INSTANCE_TYPE])[0] + EXTRA_USD


def cost_text(max_hours, size=INSTANCE_TYPE):
    """One plain line: what the next session costs at most."""
    rate = hourly_usd(size)
    return (f"Next server: {size}, about ${rate:.3f} per hour. It deletes itself after {max_hours} h, so a session "
            f"costs at most about {money(max_hours * rate)}. Data is free up to 100 GB a month.")


def uptime_text(launch_time, max_hours=MAX_HOURS, now=None, size=INSTANCE_TYPE):
    """'Running 1h05m · cost so far ~$0.02 (at most ~$0.22) · auto-deletes in 10h55m'."""
    h = ((now or datetime.now(timezone.utc)) - launch_time).total_seconds() / 3600
    left = max(0.0, max_hours - h)
    fmt = lambda x: f"{int(x)}h{int(x * 60) % 60:02d}m"
    rate = hourly_usd(size)
    return (f"Running {fmt(h)} · cost so far ~{money(h * rate)} "
            f"(at most ~{money(max_hours * rate)}) · auto-deletes in {fmt(left)}")


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
UPDATE_STEPS = [("download", "Downloading the new version", 15), ("install", "Installing it", 6)]
JOIN_STEPS = [("tunnel", "Connecting to the shared server", 6), ("verify", "Checking the connection", 4)]
REFRESH_STEPS = [("signin", "Signing in to AWS", 3), ("check", "Checking for running servers", 3)]
COLORS = {"idle": "#8e8e93", "busy": "#f5a623", "ok": "#16a34a", "warn": "#e8710a", "error": "#d93025"}
REGIONS = ["ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "eu-west-1", "eu-west-2",
           "eu-central-1", "eu-north-1", "us-east-1", "us-east-2", "us-west-2", "ca-central-1", "sa-east-1",
           "me-central-1", "af-south-1"]  # common choices; any valid region code can be typed in
THEMES = {  # graphite and green; primary = the one main button per screen
    "light": {"bg": "#f4f4f5", "card": "#ffffff", "line": "#e4e4e7", "text": "#18181b", "muted": "#5f5f66",
              "field": "#f4f4f5", "button": "#ffffff", "hover": "#ececee", "trough": "#e4e4e7", "disabled": "#a1a1aa",
              "accent": "#15803d", "accent_hover": "#166534", "accent_off": "#bbf7d0", "accent_text": "#ffffff",
              "primary": "#18181b", "primary_hover": "#3f3f46", "primary_off": "#a1a1aa", "primary_text": "#ffffff"},
    "dark": {"bg": "#0e0e10", "card": "#1a1a1d", "line": "#2c2c31", "text": "#f4f4f5", "muted": "#9b9ba3",
             "field": "#242428", "button": "#242428", "hover": "#2c2c31", "trough": "#2c2c31", "disabled": "#5f5f66",
             "accent": "#5ee38a", "accent_hover": "#86efac", "accent_off": "#1f4d30", "accent_text": "#0b0f0c",
             "primary": "#f4f4f5", "primary_hover": "#d4d4d8", "primary_off": "#3f3f46", "primary_text": "#0e0e10"},
}
THEME = dict(THEMES["light"])  # filled in by style_app() from the user's choice


def windows_uses_dark():
    """Windows' 'app mode' setting (Settings > Personalization > Colors)."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as k:
            return winreg.QueryValueEx(k, "AppsUseLightTheme")[0] == 0
    except OSError:
        return False


def resolve_theme(choice):
    return ("dark" if windows_uses_dark() else "light") if choice == "system" else choice


def dark_title_bar(window):
    """Match the window's title bar to the theme (Windows 10 2004+ / 11; silently skipped elsewhere)."""
    try:
        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        on = ctypes.c_int(1 if THEME.get("name") == "dark" else 0)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(on), ctypes.sizeof(on))
    except (AttributeError, OSError):
        pass


def scaler(root):
    """px(n): n pixels at 100 % Windows scaling, converted for this screen. Fonts are in points and
    scale by themselves; this keeps spacing in step with them on 1080p, 1440p and 4K alike."""
    k = root.winfo_fpixels("1i") / 96
    return lambda n: max(1, round(n * k))


def style_app(root, px, theme="system"):
    """Flat light or dark theme built on Tk's own 'clam' (no extra library in the exe)."""
    name = resolve_theme(theme)
    THEME.clear()
    THEME.update(THEMES[name], name=name)
    t = THEME
    root.configure(bg=t["bg"])
    for font_name in ("TkDefaultFont", "TkTextFont"):  # not option_add("*Font"): that would override ttk fonts
        tkfont.nametofont(font_name).configure(family="Segoe UI", size=11)
    for pattern, value in (("*Background", t["bg"]), ("*Foreground", t["text"]), ("*insertBackground", t["text"]),
                           ("*TCombobox*Listbox.background", t["field"]),
                           ("*TCombobox*Listbox.foreground", t["text"])):
        root.option_add(pattern, value)  # also reaches dialogs and drop-down lists
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".", background=t["bg"], foreground=t["text"], font=("Segoe UI", 11), bordercolor=t["line"],
                lightcolor=t["card"], darkcolor=t["line"], focuscolor=t["accent"])
    s.configure("Card.TFrame", background=t["card"])
    s.configure("Card.TLabel", background=t["card"])
    s.configure("Muted.Card.TLabel", background=t["card"], foreground=t["muted"])
    s.configure("Head.Card.TLabel", background=t["card"], font=("Segoe UI", 16, "bold"))
    s.configure("Title.Card.TLabel", background=t["card"], font=("Segoe UI", 11, "bold"))
    s.configure("TButton", background=t["button"], bordercolor=t["line"], lightcolor=t["button"],
                darkcolor=t["button"], padding=(px(16), px(8)), relief="flat")
    s.map("TButton", background=[("disabled", t["bg"]), ("active", t["hover"])],
          foreground=[("disabled", t["disabled"])])
    s.configure("Accent.TButton", background=t["primary"], foreground=t["primary_text"], bordercolor=t["primary"],
                lightcolor=t["primary"], darkcolor=t["primary"], font=("Segoe UI", 11, "bold"), padding=(px(26), px(8)))
    s.map("Accent.TButton", background=[("disabled", t["primary_off"]), ("active", t["primary_hover"])],
          foreground=[("disabled", t["primary_text"])])
    s.configure("Horizontal.TProgressbar", background=t["accent"], troughcolor=t["trough"], bordercolor=t["trough"],
                lightcolor=t["accent"], darkcolor=t["accent"], thickness=px(10))
    for field in ("TSpinbox", "TEntry", "TCombobox"):
        s.configure(field, fieldbackground=t["field"], foreground=t["text"], arrowcolor=t["text"],
                    arrowsize=px(11), padding=px(4), insertcolor=t["text"])
        s.map(field, fieldbackground=[("readonly", t["field"])], foreground=[("readonly", t["text"])],
              selectbackground=[("readonly", t["field"])], selectforeground=[("readonly", t["text"])])
    s.configure("Card.TCheckbutton", background=t["card"], indicatorbackground=t["field"],
                indicatorforeground=t["text"])
    s.map("Card.TCheckbutton", background=[("active", t["card"])],
          indicatorbackground=[("selected", t["accent"]), ("active", t["field"])],
          indicatorforeground=[("selected", t["accent_text"])])
    s.configure("TNotebook", background=t["bg"], borderwidth=0, tabmargins=(0, 0, 0, 0))
    s.configure("TNotebook.Tab", background=t["bg"], foreground=t["muted"], padding=(px(14), px(7)),
                bordercolor=t["line"], lightcolor=t["bg"])
    s.map("TNotebook.Tab", background=[("selected", t["card"])], foreground=[("selected", t["text"])],
          lightcolor=[("selected", t["card"])])
    s.configure("Outline.TButton", background=t["card"], foreground=t["accent"], bordercolor=t["accent"],
                lightcolor=t["card"], darkcolor=t["card"], borderwidth=1, relief="solid",
                font=("Segoe UI", 10, "bold"), padding=(px(14), px(6)))
    s.map("Outline.TButton", background=[("active", t["hover"])],
          foreground=[("disabled", t["disabled"])], bordercolor=[("disabled", t["line"])])
    s.configure("Link.TButton", background=t["card"], foreground=t["accent"], relief="flat", borderwidth=0,
                padding=(0, 0), focuscolor=t["card"])
    s.map("Link.TButton", background=[("active", t["card"])], foreground=[("active", t["accent_hover"])])


def startup_mode(joined, tunnel_running):
    """'resume' when something is already running (show it), else 'choose' (ask own server or join)."""
    return "resume" if joined or tunnel_running else "choose"


def theme_label():
    """Text for the corner switch: what pressing it changes to."""
    return "\u2600  Light" if THEME.get("name") == "dark" else "\u263e  Dark"


def info_window(parent, title, text, px):
    """A readable, scrollable help window in the current theme."""
    w = tk.Toplevel(parent)
    w.title(title)
    w.transient(parent)
    w.configure(bg=THEME["bg"])
    dark_title_bar(w)
    box = card(w, px)
    box.pack(fill="both", expand=True, padx=px(18), pady=px(18))
    txt = scrolledtext.ScrolledText(box, wrap="word", width=78, height=22, relief="flat", borderwidth=0,
                                    bg=THEME["card"], fg=THEME["text"], font=("Segoe UI", 10), padx=px(4))
    txt.insert("1.0", text)
    for line in [ln for ln in text.splitlines() if ln.isupper()]:  # section titles in bold
        start = txt.search(line, "1.0")
        txt.tag_add("h", start, f"{start} lineend")
    txt.tag_configure("h", font=("Segoe UI", 10, "bold"))
    txt.config(state="disabled")
    txt.pack(fill="both", expand=True)
    ttk.Button(box, text="Close", command=w.destroy).pack(anchor="e", pady=(px(10), 0))


def sharing_agreement(parent, px):
    """One-time acknowledgement before sharing is turned on. Returns True only if every point is ticked."""
    if load_settings()["sharing_agreed"]:
        return True
    w = tk.Toplevel(parent)
    w.title("Before you share your server")
    w.transient(parent)
    w.grab_set()
    w.resizable(False, False)
    w.configure(bg=THEME["bg"])
    dark_title_bar(w)
    box = card(w, px)
    box.pack(fill="both", expand=True, padx=px(18), pady=px(18))
    ttk.Label(box, text="Tick each point to confirm you understand:", style="Title.Card.TLabel").pack(anchor="w")
    ticks = [tk.BooleanVar() for _ in AGREEMENT_POINTS]
    result = {"ok": False}
    points = ttk.Frame(box, style="Card.TFrame")
    points.pack(fill="x")
    bar = ttk.Frame(box, style="Card.TFrame")
    agree = ttk.Button(bar, text="I agree, turn sharing on", style="Accent.TButton", state="disabled")
    for row, (point, var) in enumerate(zip(AGREEMENT_POINTS, ticks)):
        ttk.Checkbutton(points, variable=var, style="Card.TCheckbutton",
                        command=lambda: agree.config(state="normal" if all(v.get() for v in ticks) else "disabled")
                        ).grid(row=row, column=0, sticky="nw", pady=(px(10), 0))
        ttk.Label(points, text=point, style="Card.TLabel", wraplength=px(480), justify="left").grid(
            row=row, column=1, sticky="w", pady=(px(10), 0))
    ttk.Label(box, text="AWS Acceptable Use Policy: aws.amazon.com/aup", style="Muted.Card.TLabel").pack(
        anchor="w", pady=(px(12), 0))

    def accept():
        result["ok"] = True
        save_settings({"sharing_agreed": True})
        w.destroy()
    agree.config(command=accept)
    bar.pack(fill="x", pady=(px(14), 0))
    agree.pack(side="right")
    ttk.Button(bar, text="Cancel", command=w.destroy).pack(side="right", padx=px(8))
    w.wait_window()
    return result["ok"]


def switch(parent, var, command, px):
    """On/off slider (ttk has none). Click, Space or Enter flips var, then calls command."""
    w, h = px(46), px(24)
    c = tk.Canvas(parent, width=w, height=h, highlightthickness=0, bd=0, cursor="hand2", takefocus=1)

    def draw(*_):
        t, on, r = THEME, var.get(), h // 2
        c.delete("all")
        c.config(bg=t["card"])
        c.create_line(r, r, w - r, r, width=h - 2, capstyle="round", fill=t["accent"] if on else t["muted"])
        x = w - r if on else r
        ring = t["text"] if c.focus_get() is c else "#ffffff"  # visible keyboard focus
        c.create_oval(x - r + 3, 3, x + r - 3, h - 3, fill="#ffffff", outline=ring, width=2)

    def flip(_=None):
        var.set(not var.get())
        command()

    var.trace_add("write", draw)
    for ev in ("<Button-1>", "<space>", "<Return>"):
        c.bind(ev, flip)
    c.bind("<FocusIn>", draw)
    c.bind("<FocusOut>", draw)
    c.draw, c.flip = draw, flip
    draw()
    return c


def rounded(c, x1, y1, x2, y2, r, **kw):
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r,
           x1, y1 + r, x1, y1]
    return c.create_polygon(pts, smooth=True, **kw)


def path_map(parent, px):
    """Live map of the connection: This laptop -> server -> Internet, as chips joined by curves.
    show(tone, server_label) redraws it; the links take the status colour (grey idle, amber busy, green ok)."""
    h = px(64)
    c = tk.Canvas(parent, height=h, highlightthickness=0, bd=0)
    font = tkfont.Font(family="Segoe UI", size=10)
    state = {"tone": "idle", "server": "Your server"}

    def draw(*_):
        t, tone = THEME, state["tone"]
        c.delete("all")
        c.config(bg=t["card"])
        w, pad, dot = c.winfo_width(), px(12), px(8)
        if w < px(200):
            return
        labels = ["This laptop", state["server"], "Internet"]
        widths = [font.measure(x) + 2 * pad + dot + px(8) for x in labels]
        ch, ys = px(30), [px(4), h - px(34), px(4)]  # the middle chip sits lower, so the links curve
        xs = [1, (w - widths[1]) // 2, w - widths[2] - 1]
        color = COLORS[tone]
        for i in (0, 1):
            ax, ay = xs[i] + widths[i], ys[i] + ch // 2
            bx, by = xs[i + 1], ys[i + 1] + ch // 2
            mid = (ax + bx) / 2
            c.create_line(ax, ay, mid, ay, mid, by, bx, by, smooth=True, width=2, fill=color,
                          dash=() if tone == "ok" else (4, 4))
        for x, y, wd, label in zip(xs, ys, widths, labels):
            rounded(c, x, y, x + wd, y + ch, px(10), fill=t["field"], outline=t["line"])
            cy = y + ch // 2
            c.create_oval(x + pad, cy - dot // 2, x + pad + dot, cy + dot // 2, fill=color, outline="")
            c.create_text(x + pad + dot + px(8), cy, text=label, anchor="w", font=font, fill=t["text"])

    def show(tone=None, server=None):
        state.update({k: v for k, v in (("tone", tone), ("server", server)) if v})
        draw()

    c.bind("<Configure>", draw)
    c.show, c.draw = show, draw
    return c


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
        self.connected_ip, self.health_failures, self.data_used, self.server_ip = None, 0, None, None
        self.over_limit_warned = None
        self.steps, self.step_index, self.step_started = None, 0, 0.0
        os.makedirs(APP_DIR, exist_ok=True)
        moved = migrate_old_files()

        root.title(f"Proxy on demand {__version__}")
        px = self.px = scaler(root)  # every size below is in "100 % scaling" pixels, scaled to this screen
        style_app(root, px)  # follows Windows' light/dark setting; the corner switch changes it for this session
        dark_title_bar(root)
        self.joined = load_settings()["joined"] or None

        outer = ttk.Frame(root, padding=px(22))
        outer.pack(fill="both", expand=True)

        # status card: colored dot, headline, detail, and the progress bar while something runs
        status = card(outer, px)
        status.pack(fill="x")
        self.dot = tk.Label(status, text="●", font=("Segoe UI", 22), fg=COLORS["idle"], bg=THEME["card"])
        self.dot.grid(row=1, column=0, sticky="n", padx=(0, px(10)))
        self.status, self.detail = tk.StringVar(value="Checking..."), tk.StringVar()
        ttk.Label(status, textvariable=self.status, style="Head.Card.TLabel", wraplength=px(640)).grid(
            row=1, column=1, sticky="w")
        ttk.Label(status, textvariable=self.detail, style="Muted.Card.TLabel", justify="left",
                  wraplength=px(640)).grid(row=2, column=1, sticky="w", pady=(px(4), 0))
        corner = ttk.Frame(status, style="Card.TFrame")
        corner.grid(row=0, column=0, columnspan=2, sticky="e")  # own row: never collides with a long headline
        self.mode_btn = ttk.Button(corner, style="Link.TButton", command=self.switch_mode)
        self.mode_btn.pack(side="left", padx=(0, px(16)))
        self.theme_btn = ttk.Button(corner, text=theme_label(), style="Link.TButton", command=self.toggle_theme)
        self.theme_btn.pack(side="left")
        status.columnconfigure(1, weight=1)
        self.path = path_map(status, px)
        self.path.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(px(14), 0))
        self.progress = ttk.Frame(status, style="Card.TFrame")  # gridded by run(), hidden by "done"
        self.bar = ttk.Progressbar(self.progress, mode="determinate", maximum=1000)
        self.bar.pack(fill="x")
        self.step_text = tk.StringVar()
        ttk.Label(self.progress, textvariable=self.step_text, style="Muted.Card.TLabel").pack(anchor="w", pady=(px(6), 0))

        # screen 1: my own server
        self.own_view = ttk.Frame(outer)
        self.controls = ttk.Frame(self.own_view)
        self.controls.pack(fill="x", pady=px(16))
        self.start_btn = ttk.Button(self.controls, text="Start", style="Accent.TButton", command=self.start)
        own_buttons = [self.start_btn, ttk.Button(self.controls, text="Stop", command=self.stop),
                       ttk.Button(self.controls, text="Refresh", command=self.refresh),
                       ttk.Button(self.controls, text="Settings", command=self.settings_dialog)]
        plan = card(self.own_view, px)
        plan.pack(fill="x")
        self.cost = tk.StringVar()
        ttk.Label(plan, textvariable=self.cost, style="Muted.Card.TLabel", wraplength=px(640),
                  justify="left").pack(side="left", fill="x", expand=True)
        ttk.Button(plan, text="Change in Settings", style="Link.TButton",
                   command=lambda: self.settings_dialog(advanced=True)).pack(side="right", anchor="n")
        self.update_cost()
        share = card(self.own_view, px)  # sharing: the switch, the link, and who is connected
        share.pack(fill="x", pady=(px(12), 0))
        head = ttk.Frame(share, style="Card.TFrame")
        head.pack(fill="x")
        self.share_head, self.share_text = tk.StringVar(value="Sharing is off"), tk.StringVar()
        ttk.Label(head, textvariable=self.share_head, style="Title.Card.TLabel").pack(side="left")
        ttk.Button(head, text="How sharing works", style="Link.TButton", command=self.sharing_help).pack(side="right")
        self.share_var = tk.BooleanVar(value=load_settings()["sharing"])
        self.share_switch = switch(head, self.share_var, self.toggle_sharing, px)
        self.share_switch.pack(side="right", padx=(0, px(16)))
        lbl = ttk.Label(head, text="Share my server", style="Card.TLabel", cursor="hand2")
        lbl.pack(side="right", padx=(0, px(8)))
        lbl.bind("<Button-1>", self.share_switch.flip)
        self.copy_btn = ttk.Button(head, text="Copy share link", style="Outline.TButton", command=self.copy_share_link)
        ttk.Label(share, textvariable=self.share_text, style="Muted.Card.TLabel", wraplength=px(640),
                  justify="left").pack(anchor="w", pady=(px(6), 0))
        self.show_sharing({"state": "on" if self.share_var.get() else "off"})

        # screen 2: a friend's server
        self.join_view = ttk.Frame(outer)
        join_controls = ttk.Frame(self.join_view)
        join_controls.pack(fill="x", pady=px(16))
        join_buttons = [ttk.Button(join_controls, text="Connect with a link", style="Accent.TButton",
                                   command=self.join_dialog),
                        ttk.Button(join_controls, text="Disconnect", command=self.stop),
                        ttk.Button(join_controls, text="Refresh", command=self.refresh)]
        about = card(self.join_view, px)
        about.pack(fill="x")
        ttk.Label(about, text="Using a friend's server", style="Title.Card.TLabel").pack(anchor="w")
        ttk.Label(about, text=JOIN_INFO, style="Muted.Card.TLabel", wraplength=px(640), justify="left").pack(
            anchor="w", pady=(px(6), 0))
        ttk.Button(about, text="How sharing works", style="Link.TButton", command=self.sharing_help).pack(
            anchor="w", pady=(px(8), 0))

        self.buttons, self.activity_btns = own_buttons + join_buttons, []
        for bar, buttons in ((self.controls, own_buttons), (join_controls, join_buttons)):
            for b in buttons:
                b.pack(side="left", padx=(0, px(8)))
            act = ttk.Button(bar, text="Show activity", command=self.toggle_activity)
            act.pack(side="right")
            self.activity_btns.append(act)
            ttk.Button(bar, text="Logs", command=lambda: os.startfile(APP_DIR)).pack(side="right", padx=px(8))

        # activity log, folded away until asked for
        self.activity = card(outer, px)
        self.out = scrolledtext.ScrolledText(self.activity, height=9, font=("Consolas", 10), state="disabled",
                                             relief="flat", borderwidth=0, bg=THEME["card"], fg=THEME["text"])
        self.out.pack(fill="both", expand=True)
        self.cards = [status, plan, share, about, self.activity]
        self.mode = None
        self.set_mode("join" if self.joined else "own")
        fit_to_screen(root, px)

        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(200, self.pump)
        root.after(300_000, self.tick)  # then poll_seconds() decides
        root.after(60_000, self.health)
        if moved:
            self.log(f"Moved your saved {' and '.join(moved)} to {APP_DIR}")
        threading.Thread(target=self.check_for_update, daemon=True).start()
        root.after(300, self.launch_choice)

    def launch_choice(self):
        """On launch: show what's running, or ask whether to run your own server or join a friend's."""
        if startup_mode(self.joined, singbox_running()) == "resume":
            self.set_mode("join" if self.joined else "own")
            return self.refresh()
        self.set_status("Welcome", "idle", "Run your own server, or join a server a friend shared with you.")
        px = self.px
        w = tk.Toplevel(self.root)
        w.title("Proxy on demand")
        w.transient(self.root)
        w.grab_set()
        w.resizable(False, False)
        w.configure(bg=THEME["bg"])
        dark_title_bar(w)
        box = card(w, px)
        box.pack(fill="both", expand=True, padx=px(18), pady=px(18))
        ttk.Label(box, text="How do you want to connect?", style="Head.Card.TLabel").pack(anchor="w")
        choice = {"go": None}
        options = (
            ("Run my own server", "Accent.TButton", "own",
             "On your own AWS account. The first time, you'll add your AWS access key next (Quick Start in the README)."),
            ("Join a friend's server", "Outline.TButton", "join",
             "Paste a link someone shared with you. No AWS account needed."),
        )
        for text, style, key, hint in options:
            ttk.Button(box, text=text, style=style, command=lambda k=key: (choice.update(go=k), w.destroy())).pack(
                fill="x", pady=(px(16), px(4)))
            ttk.Label(box, text=hint, style="Muted.Card.TLabel", wraplength=px(440), justify="left").pack(anchor="w")
        w.update_idletasks()
        w.geometry(f"+{self.root.winfo_rootx() + (self.root.winfo_width() - w.winfo_reqwidth()) // 2}"
                   f"+{self.root.winfo_rooty() + px(40)}")
        w.wait_window()
        if choice["go"] == "join":
            self.set_mode("join")
            self.set_status("Not connected", "idle", "Press Connect with a link and paste the link your friend sent.")
            self.join_dialog()
        elif choice["go"] == "own" and not load_key():
            self.set_status("Set up your AWS access", "idle", "Paste your AWS access key and choose a region, then "
                                                              "press Save. See the README Quick Start, step 5.")
            self.settings_dialog()  # opens on the AWS access tab
        elif choice["go"] == "own":
            self.refresh()

    def check_for_update(self):
        tag = newer_release()
        if tag:
            self.log(f"A new version ({tag}) is available: https://github.com/{REPO}/releases/latest")
            self.q.put(("title", f"Proxy on demand {__version__}  -  update available: {tag}"))
            self.q.put(("update", tag))

    def offer_update(self, tag):
        if self.busy:  # never interrupt Start/Stop; ask again in a minute
            return self.root.after(60_000, lambda: self.offer_update(tag))
        kind = update_kind()
        if kind == "git":
            return messagebox.showinfo("Update available", f"Version {tag} is available. This copy is a git "
                                                            f"clone, so update it with:\n\ngit pull")
        if messagebox.askyesno("Update available", (
                f"Version {tag} is available (you have {__version__}).\n\nUpdate now? The app downloads it, "
                f"checks it, replaces this version and restarts. Your connection stays up.\n\n"
                f"What's new: github.com/{REPO}/releases/tag/{tag}")):
            self.update_to(tag, kind)

    def update_to(self, tag, kind):
        def job():
            self.step("download")
            data = download_verified(tag, UPDATE_ASSETS[kind])
            self.step("install")
            if kind == "exe":
                install_exe(data, sys.executable)
            else:
                install_source(data, app_folder())
                subprocess.run([sys.executable, "-m", "pip", "install", "--user", "--quiet",
                                "--disable-pip-version-check", "-r", os.path.join(app_folder(), "requirements.txt")],
                               creationflags=NO_WINDOW, check=True)
            self.log(f"Updated to {tag}; restarting")
            self.q.put(("restart", ""))
        self.run(job, UPDATE_STEPS, f"Updating to {tag}...")

    def restart(self):
        if getattr(sys, "frozen", False):
            cmd = [sys.executable, "--after-update"]
        else:
            pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
            cmd = [pyw if os.path.exists(pyw) else sys.executable, os.path.join(app_folder(), "proxy_app.py"),
                   "--after-update"]
        subprocess.Popen(cmd, cwd=app_folder())
        self.root.destroy()

    def toggle_theme(self):
        style_app(self.root, self.px, "light" if THEME["name"] == "dark" else "dark")
        for c in self.cards:
            c.config(bg=THEME["card"], highlightbackground=THEME["line"])
        self.dot.config(bg=THEME["card"])
        self.share_switch.draw()
        self.path.draw()
        self.out.config(bg=THEME["card"], fg=THEME["text"], insertbackground=THEME["text"])
        self.theme_btn.config(text=theme_label())
        dark_title_bar(self.root)

    def show_sharing(self, info):
        """Bottom panel. info["state"]: off | on | joined, plus server/peers/mine while sharing."""
        st = info["state"]
        if st in ("on", "off") and hasattr(self, "share_var"):
            self.share_var.set(st == "on")
        self.copy_btn.pack_forget()
        if st == "joined":
            self.share_head.set("Using a friend's shared server")
            self.share_text.set(f"Connected through {info['host']} with a link someone shared. The owner can see "
                                "your IP address and which sites you visit. Press Stop to disconnect.")
        elif st == "off":
            self.share_head.set("Sharing is off")
            self.share_text.set("Only this laptop can use your server. To let people you trust use it, turn on "
                                "Share my server.")
        elif not info.get("server"):
            self.share_head.set("Sharing is on")
            self.share_text.set("Start your server to get a link. Anyone you send it to can connect while it runs.")
        else:
            peers, mine = info.get("peers"), info.get("mine", set())
            self.copy_btn.pack(side="right", padx=(0, self.px(12)))
            if peers is None:
                self.share_head.set("Sharing is on")
                lines = ["Connected devices can't be listed for this server (started by an older version, or "
                         "not reachable right now)."]
            else:
                self.share_head.set(f"Sharing is on · {len(peers)} of {SHARE_LIMIT} devices connected")
                lines = [f"•  {ip}{'  (you)' if ip in mine else ''}  ·  {n} connection{'s' if n != 1 else ''}"
                         for ip, n in sorted(peers.items(), key=lambda kv: kv[0] not in mine)] or \
                        ["Nobody is connected right now."]
                if len(peers) > SHARE_LIMIT:
                    lines.append(f"Over the limit of {SHARE_LIMIT}: your link has probably been passed on. Press Stop "
                                 "and share a fresh link only with people you trust.")
            self.share_text.set("\n".join(lines) + "\nAnyone with the link can connect while this server runs. "
                                "Turn sharing off or press Stop to cut everyone off.")
        self.root.geometry("")

    def sharing_help(self, parent=None):
        info_window(parent or self.root, "How sharing works", SHARING_HELP, self.px)

    def copy_share_link(self):
        ip = self.connected_ip or self.server_ip
        if not (load_settings()["sharing"] and ip):
            return messagebox.showinfo("Sharing", "Turn on sharing and start your server first.")
        link = share_link(ip, ss_outbound(load_config()).get("password"))
        self.root.clipboard_clear()
        self.root.clipboard_append(link)
        messagebox.showinfo("Share link copied", SHARE_REMINDER)

    def join_dialog(self):
        if self.busy:
            return
        if self.server_up:
            return messagebox.showinfo("Join a friend", "Your own server is running and billing. Press Stop first, "
                                                        "then join your friend's server.")
        w = tk.Toplevel(self.root)
        w.title("Join a friend's server")
        w.transient(self.root)
        w.grab_set()
        w.resizable(False, False)
        w.configure(bg=THEME["bg"])
        dark_title_bar(w)
        box = card(w, self.px)
        box.pack(fill="both", expand=True, padx=self.px(18), pady=self.px(18))
        ttk.Label(box, text=JOIN_WARNING, style="Card.TLabel", wraplength=self.px(520), justify="left").pack(anchor="w")
        entry = ttk.Entry(box, width=60)
        entry.pack(fill="x", pady=(self.px(12), self.px(12)))
        entry.focus_set()
        bar = ttk.Frame(box, style="Card.TFrame")
        bar.pack(fill="x")

        def connect():
            try:
                parsed = parse_link(entry.get())
            except ValueError as e:
                return messagebox.showerror("Join a friend", str(e), parent=w)
            w.destroy()
            self.join(*parsed)
        ttk.Button(bar, text="Connect", style="Accent.TButton", command=connect).pack(side="right")
        ttk.Button(bar, text="Cancel", command=w.destroy).pack(side="right", padx=self.px(8))
        ttk.Button(bar, text="How sharing works", style="Link.TButton",
                   command=lambda: self.sharing_help(w)).pack(side="left")
        entry.bind("<Return>", lambda e: connect())

    def join(self, host, port, method, password):
        def job():
            self.step("tunnel")
            try:
                ip = socket.gethostbyname(host)
            except OSError:
                raise RuntimeError(f"Can't find the server {host}. Ask for the link again.") from None
            if warp_connected():
                warp_disconnect()
                self.warp_was_on = True
            stop_singbox()
            start_singbox(find_singbox() or install_singbox(self.log), make_join_config(ip, port, method, password))
            self.step("verify")
            got = None
            for _ in range(6):
                try:
                    got = egress_ip()
                    break
                except OSError:
                    time.sleep(3)
            if got != ip:
                stop_singbox()
                raise RuntimeError("Couldn't connect through the shared server. Its owner may have sharing off, or "
                                   "the server has stopped (links work only while the owner's server runs). Ask "
                                   "them to check, or for a fresh link.")
            self.joined, self.connected_ip, self.health_failures = ip, ip, 0
            save_settings({"joined": ip})
            self.log(f"Connected to a friend's server: {ip}")
            self.report_joined()
        self.run(job, JOIN_STEPS, "Joining...")

    def report_joined(self):
        """Connected to a friend's server: no AWS involved."""
        ok = False
        if singbox_running():
            try:
                ok = egress_ip() == self.joined
            except OSError:
                pass
        if ok:
            self.connected_ip = self.joined
            self.set_status(f"Connected to a friend's server ({self.joined})", "ok",
                            "Their server, their bill. Press Stop to disconnect.")
            self.q.put(("sharing", {"state": "joined", "host": self.joined}))
        else:
            self.leave_join()
            self.set_status("Disconnected from your friend's server", "warn",
                            "Their server stopped or they turned sharing off. Ask for a fresh link, then press "
                            "Join a friend.")
            self.q.put(("sharing", {"state": "on" if load_settings()["sharing"] else "off"}))
        self.q.put(("start_label", "Start"))

    def leave_join(self):
        stop_singbox()
        self.joined = self.connected_ip = None
        save_settings({"joined": ""})

    def toggle_activity(self):
        showing = not self.activity.winfo_ismapped()
        if showing:
            self.activity.pack(fill="both", expand=True, pady=(self.px(14), 0))
        else:
            self.activity.pack_forget()
        for b in self.activity_btns:
            b.config(text="Hide activity" if showing else "Show activity")
        self.root.geometry("")  # let the window grow or shrink to its content

    def set_mode(self, mode):
        """Show one screen: 'own' (run my own server) or 'join' (use a friend's server)."""
        self.mode = mode
        hide, show = (self.join_view, self.own_view) if mode == "own" else (self.own_view, self.join_view)
        hide.pack_forget()
        if self.activity.winfo_ismapped():
            show.pack(fill="x", before=self.activity)
        else:
            show.pack(fill="x")
        self.mode_btn.config(text="Use a friend's server instead" if mode == "own" else "Run my own server instead")
        self.path.show(server="Your server" if mode == "own" else "Friend's server")
        self.root.geometry("")

    def switch_mode(self):
        if self.busy:
            return
        if self.mode == "own":
            if self.server_up:
                return messagebox.showinfo("Proxy on demand", "Your own server is running and billing. Press Stop "
                                                              "first, then switch to a friend's server.")
            self.set_mode("join")
            self.set_status("Not connected", "idle", "Press Connect with a link and paste the link your friend sent.")
            return
        if self.joined:
            if not messagebox.askyesno("Proxy on demand", "Disconnect from your friend's server?"):
                return
            self.leave_join()
            self.log("Disconnected from your friend's server")
        self.set_mode("own")
        self.refresh()

    def toggle_sharing(self):
        on = self.share_var.get()
        if self.busy:  # never change the firewall in the middle of Start or Stop
            return self.share_var.set(not on)
        if on and not sharing_agreement(self.root, self.px):
            return self.share_var.set(False)
        save_settings({"sharing": on})
        if self.server_up:
            self.log("Sharing " + ("turned on: opening" if on else "turned off: closing") + " the server's firewall")
            self.start()  # Reconnect: re-applies the firewall for the new setting
        else:
            self.show_sharing({"state": "on" if on else "off", "server": False})

    def update_cost(self):
        s = load_settings()
        cap = ("Going over the free 100 GB of data is allowed." if s["allow_over"] else
               "It also stops itself at 99.99 GB of data for the month, so data stays free.")
        self.cost.set(cost_text(s["max_hours"], s["size"]) + " " + cap)

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
                self.path.show(tone)
            elif kind == "step":
                keys = [s[0] for s in self.steps or []]
                if msg in keys:
                    self.step_index, self.step_started = keys.index(msg), time.time()
            elif kind == "sharing":
                self.show_sharing(msg)
            elif kind == "update":
                self.offer_update(msg)
            elif kind == "restart":
                self.root.after(500, self.restart)  # after "done" has been handled
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
        self.progress.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(self.px(14), 0))
        self.status.set(headline)
        self.detail.set("")
        self.dot.config(fg=COLORS["busy"])
        self.path.show("busy")
        self.animate()

        def wrapped():
            try:
                job()
            except NoKeyError as e:
                self.log(str(e))
                self.set_status("Welcome! Not set up yet", "idle",
                                "To run your own server: open Settings and add your AWS key (README, Quick Start). "
                                "To use a friend's server: press Join a friend and paste their link.")
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
                + ("Going over is allowed in Settings, so your server keeps running. Data beyond 100 GB costs "
                   "about $0.09-0.11 per GB." if allow_over else
                   f"When it reaches 99.99 GB your server stops itself, so you are not charged for data. You have "
                   f"{gb(max(0, CAP_BYTES - used))} left.")
                + "\n\nThe free 100 GB resets on the 1st of each month (UTC). It is shared with anything else on "
                  "your AWS account that sends data to the internet.")))
        if capped:
            self.q.put(("warn", "Your server stopped itself: this month's free 100 GB of data is used up.\n\n"
                                "This keeps you from being charged for data. You can start again on the 1st of next "
                                "month (UTC), or tick \"Allow going over the free 100 GB\" in Settings if you "
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
            up = uptime_text(i["LaunchTime"], server_hours(i), size=i.get("InstanceType", INSTANCE_TYPE)) + "\n" + data
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
                            "(UTC), or allow going over in Settings.\n" + data)
        settings = load_settings()
        info = {"state": "on" if settings["sharing"] else "off", "server": bool(insts)}
        self.server_ip = insts[0].get("PublicIpAddress") if insts else None
        if insts and settings["sharing"] and self.server_ip:
            info.update(peers=server_peers(self.server_ip, tag(insts[0], "status-token")),
                        mine=aws.owner_ips(insts[0]))
            if info["peers"] and len(info["peers"]) > SHARE_LIMIT and self.over_limit_warned != self.server_ip:
                self.over_limit_warned = self.server_ip  # once per server
                self.q.put(("warn", f"{len(info['peers'])} devices are using your server, more than the limit of "
                                    f"{SHARE_LIMIT}.\n\nYour link has probably been passed on. You pay for all of "
                                    "them and are responsible for their traffic. Press Stop (the next server gets a "
                                    "new link), then share it only with people you trust."))
        self.q.put(("sharing", info))
        self.q.put(("start_label", "Reconnect" if insts else "Start"))
        self.first_check = False

    def refresh(self):
        def job():
            if self.joined:
                return self.report_joined()
            if self.mode == "join":
                return self.set_status("Not connected", "idle",
                                       "Press Connect with a link and paste the link your friend sent.")
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
                if self.joined:
                    self.log("Connection check failed twice: the shared server isn't reachable.")
                    self.set_status("Connection lost", "error", "The shared server stopped or its owner turned "
                                    "sharing off. Press Refresh, or ask for a fresh link.")
                    return
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
                raise NoKeyError("No AWS key saved yet. Open Settings.")
            if not settings["mfa"]:
                self.session, self.session_expiry = key_session(record), None
                return Aws(self.log, settings, self.session)
            if "role_arn" not in record:
                raise NoKeyError("MFA is turned on, but the saved key was set up without it. "
                                 "Open Settings and save again.")
            code = self.ask_mfa()
            if code is None:
                raise SignInCancelled("Not signed in. Press Refresh or Start to sign in with your MFA code.")
            self.session, self.session_expiry = assume(record, code.strip(), settings["region"])
            self.log(f"Signed in with MFA until {self.session_expiry.astimezone():%H:%M} (credentials kept in memory only)")
        return Aws(self.log, settings, self.session)

    def settings_dialog(self, advanced=False):
        if self.busy:
            return
        s, px = load_settings(), self.px
        w = tk.Toplevel(self.root)
        w.title("Settings")
        w.transient(self.root)
        w.grab_set()
        w.resizable(False, False)
        w.configure(bg=THEME["bg"])
        dark_title_bar(w)
        body = ttk.Frame(w, padding=px(18))
        body.pack(fill="both", expand=True)

        def section(parent, title):
            c = card(parent, px)
            ttk.Label(c, text=title, style="Title.Card.TLabel").grid(row=0, column=0, columnspan=2, sticky="w",
                                                                     pady=(0, px(6)))
            c.columnconfigure(1, weight=1)
            return c

        def note(parent, row, text="", var=None):
            label = ttk.Label(parent, text=text, textvariable=var, style="Muted.Card.TLabel",
                              wraplength=px(560), justify="left")
            label.grid(row=row, column=0, columnspan=2, sticky="w", pady=(0, px(6)))
            return label

        def field(parent, row, label, widget):
            ttk.Label(parent, text=label, style="Card.TLabel").grid(row=row, column=0, sticky="w",
                                                                    padx=(0, px(12)), pady=px(4))
            widget.grid(row=row, column=1, sticky="ew", pady=px(4))
            return widget

        # tabs: the first holds everything a beginner needs; the rest are optional
        tabs = ttk.Notebook(body)
        tabs.pack(fill="both", expand=True)
        pages = {}
        for name in ("AWS access", "Server & data", "Security"):
            pages[name] = ttk.Frame(tabs, padding=(0, px(12), 0, 0))
            tabs.add(pages[name], text=name)

        basic = section(pages["AWS access"], "AWS access")
        basic.pack(fill="x")
        key_id = field(basic, 1, "Access key ID", ttk.Entry(basic, width=46))
        secret = field(basic, 2, "Secret access key", ttk.Entry(basic, width=46, show="•"))
        region = field(basic, 3, "Region", ttk.Combobox(basic, values=REGIONS, width=44))
        region.set(s["region"])
        note(basic, 4, "Leave the key fields empty to keep the key already saved. It is stored encrypted for your "
                       "Windows account and never shown again. Choose the AWS region nearest to you.")
        ttk.Button(basic, text="Copy IAM policy", style="Outline.TButton", command=lambda: copy_user_policy()).grid(
            row=5, column=0, columnspan=2, sticky="w")

        server = section(pages["Server & data"], "Server")
        server.pack(fill="x")
        size_names = {f"{k}  -  {v[1]}": k for k, v in SERVER_SIZES.items()}
        size = field(server, 1, "Size", ttk.Combobox(server, values=list(size_names), state="readonly", width=60))
        size.set(next(n for n, k in size_names.items() if k == s["size"]))
        hours = tk.StringVar(value=str(s["max_hours"]))
        row = ttk.Frame(server, style="Card.TFrame")
        field(server, 2, "Delete after", row)
        ttk.Spinbox(row, from_=1, to=MAX_HOURS_LIMIT, width=4, textvariable=hours, justify="center").pack(side="left")
        ttk.Label(row, text="hours, even if you never press Stop", style="Card.TLabel").pack(side="left", padx=px(8))
        estimate = tk.StringVar()
        note(server, 3, var=estimate)

        def update_estimate(*_):
            k, h = size_names.get(size.get(), INSTANCE_TYPE), clamp_hours(hours.get())
            estimate.set(f"Estimate: about ${hourly_usd(k):.3f} per hour while it runs, at most "
                         f"{money(h * hourly_usd(k))} per session ({h} h). Mumbai prices; other regions differ "
                         "a little. Bigger servers handle more people at once.")
        size.bind("<<ComboboxSelected>>", update_estimate)
        hours.trace_add("write", update_estimate)
        update_estimate()

        data = section(pages["Server & data"], "Data")
        data.pack(fill="x", pady=(px(12), 0))
        over = tk.BooleanVar(value=s["allow_over"])
        ttk.Checkbutton(data, text="Allow going over the free 100 GB of data a month", variable=over,
                        style="Card.TCheckbutton").grid(row=1, column=0, columnspan=2, sticky="w")
        note(data, 2, "Off (recommended): a server stops itself at 99.99 GB of data for the month, so data never "
                      "costs you anything. On: no limit; beyond 100 GB you pay about $0.09-0.11 per GB.")

        sec = section(pages["Security"], "Extra security")
        sec.pack(fill="x")
        mfa = tk.BooleanVar(value=s["mfa"])
        ttk.Checkbutton(sec, text="Require a code from my phone (MFA)", variable=mfa, style="Card.TCheckbutton",
                        command=lambda: update_mode()).grid(row=1, column=0, columnspan=2, sticky="w")
        mode_note = note(sec, 2)
        role_bar = ttk.Frame(sec, style="Card.TFrame")
        role_bar.grid(row=3, column=0, columnspan=2, sticky="w", pady=(0, px(6)))
        role_buttons = [ttk.Button(role_bar, text="Copy role trust policy", style="Outline.TButton",
                                   command=lambda: copy_trust_policy()),
                        ttk.Button(role_bar, text="Copy role permissions", style="Outline.TButton",
                                   command=lambda: copy_role_permissions())]
        for b in role_buttons:
            b.pack(side="left", padx=(0, px(8)))
        ssm_role = field(sec, 4, "Session Manager role", ttk.Entry(sec, width=40))
        ssm_role.insert(0, s["ssm_role"])
        note(sec, 5, "Optional: an EC2 role that lets you open a shell on the server from the AWS console.")


        def update_mode():
            mode_note.config(text=(
                "On: your access key alone can do nothing. Each sign-in also needs a code from your phone, and AWS "
                "access lasts 1 hour, in memory only. Needs a role in AWS (README: Extra security with MFA)."
                if mfa.get() else
                "Off (simplest): the key itself holds the app's limited permissions. If it were stolen, it could only "
                "start and delete the app's small servers; every other safeguard stays."))
            for b in role_buttons:
                b.config(state="normal" if mfa.get() else "disabled")

        def region_ok():
            r = region.get().strip()
            if not valid_region(r):
                messagebox.showerror("Settings", "Enter a region code such as ap-south-1.", parent=w)
                return None
            return r

        def copy(text, guide):
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            title, steps, anchor = COPY_GUIDES[guide]
            if messagebox.askyesno(title, f"Copied to the clipboard. Now, in the AWS console:\n\n{steps}\n\n"
                                          "Open the step-by-step guide in your browser?", parent=w):
                webbrowser.open(f"https://github.com/{REPO}#{anchor}")

        def typed_or_saved_record():
            kid, sec_ = key_id.get().strip(), secret.get().strip()
            if kid or sec_:
                w.config(cursor="watch")
                w.update()
                try:
                    return inspect_key(kid, sec_)[0]
                finally:
                    w.config(cursor="")
            return load_key()

        def copy_user_policy():
            if mfa.get():
                copy(json.dumps(key_policy(), indent=2), "mfa_user")
                return
            r = region_ok()
            if r:  # no MFA: the user itself holds the least-privilege EC2 permissions
                copy(json.dumps(iam_policy(r, ssm_role.get().strip()), indent=2), "user")

        def copy_role_permissions():
            r = region_ok()
            if r:
                copy(json.dumps(iam_policy(r, ssm_role.get().strip()), indent=2), "role_permissions")

        def copy_trust_policy():
            try:
                record = typed_or_saved_record()
            except Exception as e:
                return messagebox.showerror("Settings", str(e), parent=w)
            if not record:
                return messagebox.showerror("Settings", "Enter the access key first: the trust policy names "
                                            "the user that owns it.", parent=w)
            copy(json.dumps(trust_policy(record["user_arn"]), indent=2), "trust")

        def save():
            r = region_ok()
            if not r:
                return
            if r != s["region"] and self.server_up:  # would orphan a billing server in the old region
                return messagebox.showerror("Settings", "Press Stop before changing the region, so the server in "
                                            "the current region is deleted.", parent=w)
            kid, sec_ = key_id.get().strip(), secret.get().strip()
            saved = load_key()
            if not (kid or sec_) and saved and mfa.get() != s["mfa"]:
                kid, sec_ = saved["key_id"], saved["secret"]  # MFA switched: re-check the saved key
            if kid or sec_:
                w.config(cursor="watch")
                w.update()
                try:
                    record, warnings = inspect_key(kid, sec_, mfa.get(), r)
                except Exception as e:
                    return messagebox.showerror("Settings", f"This key cannot be used:\n\n{e}", parent=w)
                finally:
                    w.config(cursor="")
                if warnings and not messagebox.askyesno(
                        "Key works, but...", "\n\n".join(warnings) + "\n\nSave this key anyway?", parent=w):
                    return
                save_key(record)
                self.log(f"AWS key saved, encrypted (user {record['user_arn'].split('/')[-1]})")
            save_settings({"mfa": mfa.get(), "region": r, "ssm_role": ssm_role.get().strip(),
                           "allow_over": over.get(), "max_hours": clamp_hours(hours.get()),
                           "size": size_names[size.get()]})
            self.session = None  # settings or key changed: sign in again
            self.update_cost()
            w.destroy()
            self.refresh()  # signs in (with the MFA code if enabled) and proves the setup works

        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(px(16), 0))
        ttk.Button(buttons, text="Save", style="Accent.TButton", command=save).pack(side="right")
        ttk.Button(buttons, text="Cancel", command=w.destroy).pack(side="right", padx=px(8))
        update_mode()
        if advanced:
            tabs.select(pages["Server & data"])
        w.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - w.winfo_reqwidth()) // 2
        w.geometry(f"+{max(0, x)}+{max(0, self.root.winfo_rooty() - px(20))}")

    def start(self):
        settings = load_settings()
        hours, size, sharing = settings["max_hours"], settings["size"], settings["sharing"]

        def job():
            if self.joined:
                self.log("Leaving your friend's server to start your own")
                self.leave_join()
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
            aws.allow_only(sg, allowed, sharing)

            def recheck():  # networks with several public IPs: allow any we had not seen yet
                new = my_ips(rounds=2) - allowed
                if new:
                    allowed.update(new)
                    aws.allow_only(sg, allowed, sharing)
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
                    launched = aws.launch(password, sg, subnet, hours, cap, size)
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
            server_h, rate = server_hours(inst), hourly_usd(inst.get("InstanceType", INSTANCE_TYPE))
            self.q.put(("popup", f"Successfully connected.\n\nYour traffic now leaves via {got} ({aws.region}).\n\n"
                                 f"Press Stop when you are done. Otherwise the server deletes itself after "
                                 f"{server_h} h (at most about {money(server_h * rate)}).\n\n"
                                 "Changed network (e.g. Wi-Fi to mobile data) and it stops working? "
                                 "Press Reconnect."))
        self.run(job, START_STEPS, "Reconnecting..." if self.server_up else "Starting...")

    def data_allowance(self, aws):
        """Bytes the new server may send before it stops itself (0 = no limit, the user allowed going over)."""
        if load_settings()["allow_over"]:
            self.log("No data limit on this server: going over the free 100 GB is allowed in Settings")
            return 0
        used = self.usage(aws)
        if used is None:
            raise RuntimeError(
                "The app can't read this month's data usage, so it can't guarantee the server stops before the free "
                "100 GB.\n\nUpdate your IAM policy: Settings > Copy IAM policy (or Copy role permissions if MFA "
                "is off), then in the AWS console replace the proxy-on-demand-ec2 policy's JSON with it. "
                "Or tick \"Allow going over the free 100 GB\" in Settings.")
        left = CAP_BYTES - int(used)
        if left < 200 * 10**6:
            raise RuntimeError(
                f"This month's free 100 GB of data is used up ({gb(used)} so far), so Start is blocked to keep you "
                "from being charged.\n\nIt resets on the 1st of next month (UTC). To start anyway, tick \"Allow going "
                "over the free 100 GB\" in Settings (data beyond it costs about $0.09-0.11 per GB).")
        self.log(f"This server may send {gb(left)} more this month; it stops itself at the limit")
        return left

    def stop(self):
        def job():
            self.step("disconnect")
            if self.joined:
                self.log("Disconnected from your friend's server")
                self.leave_join()
                self.set_status("Not connected", "idle", "You left your friend's server.")
                return
            if self.mode == "join":
                return self.set_status("Not connected", "idle", "You aren't connected to a friend's server.")
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
        friends = ("\n\nSharing is on: anyone using your link is cut off too if you choose Yes." if
                   load_settings()["sharing"] and self.server_up else "")
        ans = messagebox.askyesnocancel("Quit", "Stop the proxy and delete the server before quitting?\n\n"
                                                "Yes = stop everything, nothing keeps billing.\n"
                                                "No = stay connected with the window closed. The server keeps "
                                                "billing until it deletes itself at the time you chose; open "
                                                "the app again any time to see it or press Stop." + friends)
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


UPDATE_ASSETS = {"exe": "ProxyOnDemand.exe", "source": "proxy-on-demand-source.zip"}


def app_folder():
    return os.path.dirname(sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__))


def update_kind(folder=None):
    """How this copy runs: the packaged exe, a source download, or a git clone (updated with git pull)."""
    if getattr(sys, "frozen", False):
        return "exe"
    return "git" if os.path.isdir(os.path.join(folder or app_folder(), ".git")) else "source"


def download_verified(tag, name, opener=None):
    """Download a release file and check it against the release's published SHA-256. Raises on mismatch."""
    opener = opener or (lambda url: urllib.request.urlopen(url, timeout=180))
    base = f"https://github.com/{REPO}/releases/download/{tag}/{name}"
    with opener(base) as r:
        data = r.read()
    with opener(base + ".sha256") as r:
        expected = r.read().decode().split()[0].lower()
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError("The download didn't match its checksum, so nothing was changed. Try again later.")
    return data


def install_exe(data, exe):
    """Swap in the new exe. Windows lets a running exe be renamed (not deleted), so the old one becomes
    .old and is deleted on the next start."""
    new, old = exe + ".new", exe + ".old"
    with open(new, "wb") as f:
        f.write(data)
    if os.path.exists(old):
        os.remove(old)
    os.replace(exe, old)
    os.replace(new, exe)


def install_source(data, folder):
    """Overwrite the app's files with the new version's. Your settings and key live elsewhere and are untouched."""
    root = os.path.abspath(folder)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        entries = [e for e in z.infolist() if not e.is_dir()]
        for e in entries:  # check every path first: nothing may land outside the app folder
            target = os.path.abspath(os.path.join(root, e.filename))
            if os.path.commonpath([root, target]) != root:
                raise RuntimeError("The update contains an unsafe file path, so nothing was changed.")
        for e in entries:
            target = os.path.join(root, e.filename)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as f:
                f.write(z.read(e))


def remove_old_exe():
    if getattr(sys, "frozen", False):
        try:
            os.remove(sys.executable + ".old")
        except OSError:
            pass


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


def already_running(wait=0.0):
    """One window at a time: two copies would fight over the same server and tunnel. After an update the
    new copy waits a few seconds for the old one to close."""
    k32, end = ctypes.windll.kernel32, time.time() + wait
    while True:
        already_running.handle = k32.CreateMutexW(None, False, "Local\\proxy-on-demand")
        if k32.GetLastError() != 183:  # 183 = ERROR_ALREADY_EXISTS
            return False
        k32.CloseHandle(already_running.handle)
        if time.time() >= end:
            return True
        time.sleep(0.5)


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
    remove_old_exe()
    if already_running(wait=20 if "--after-update" in sys.argv else 0):
        messagebox.showinfo("Proxy on demand", "Proxy on demand is already open. Use the window that is open.")
        sys.exit(0)
    root = tk.Tk()
    App(root)
    root.mainloop()
