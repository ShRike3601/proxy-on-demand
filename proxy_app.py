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
import secrets
import urllib.parse
import urllib.request
import webbrowser
import zipfile
from datetime import datetime, timedelta, timezone

__version__ = "2.0.1"
REPO = "ShRike3601/proxy-on-demand"  # GitHub repo, for the "new version available" notice
ROLE_NAME = "proxy-on-demand-role"  # IAM role holding the app's EC2 permissions; assumable only with MFA
SESSION_SECONDS = 3600              # temporary credentials last 1 hour, in memory only
OLD_PROFILE = "proxy-on-demand"     # plain-text profile used by earlier versions; removed on first save
APP_TAG = "ss-proxy-app"          # every resource we create is tagged app=ss-proxy-app
# Server sizes offered in Settings > Advanced. x86 only: the server installs the x86_64 Shadowsocks build.
# Prices: on-demand Linux, Mumbai (ap-south-1), approximate; other regions differ a little.
SERVER_SIZES = {
    "t3.micro": (0.0112, "Small: 1 GB memory. Plenty for 1-3 people (default)"),  # Mumbai price: fallback only
    "t3.small": (0.0224, "Medium: 2 GB memory, about twice Small's steady network share. A few people"),
    "t3.medium": (0.0448, "Large: 4 GB memory, about four times Small's steady network share. A small group"),
}
INSTANCE_TYPE = "t3.micro"  # default size
DISK_GB = 8  # Amazon Linux 2023's root disk (gp3)
REGION_NAMES = {
    "ap-south-1": "Mumbai", "ap-southeast-1": "Singapore", "ap-southeast-2": "Sydney", "ap-northeast-1": "Tokyo",
    "eu-west-1": "Ireland", "eu-west-2": "London", "eu-central-1": "Frankfurt", "eu-north-1": "Stockholm",
    "us-east-1": "N. Virginia", "us-east-2": "Ohio", "us-west-2": "Oregon", "ca-central-1": "Canada",
    "sa-east-1": "São Paulo", "me-central-1": "UAE", "af-south-1": "Cape Town",
}
BUDGET_NAME = "proxy-on-demand"  # a free AWS Budgets budget limited to the app's tag: AWS's own figure
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
        {"Sid": "ThisAppsBudget", "Effect": "Allow", "Action": ["budgets:ViewBudget", "budgets:ModifyBudget"],
         "Resource": f"arn:aws:budgets::*:budget/{BUDGET_NAME}"},  # AWS's own figure for the app, free to read
        {"Sid": "CreditsLeft", "Effect": "Allow", "Action": "freetier:GetAccountPlanState", "Resource": "*"},
        {"Sid": "LatestAmazonLinuxAmi", "Effect": "Allow", "Action": "ssm:GetParameter",
         "Resource": f"arn:aws:ssm:{region}::parameter/aws/service/ami-amazon-linux-latest/*"},
    ]
    if ssm_role:
        statements.append({"Sid": "PassSessionManagerRole", "Effect": "Allow", "Action": "iam:PassRole",
                           "Resource": f"arn:aws:iam::*:role/{ssm_role}",
                           "Condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}})
    return {"Version": "2012-10-17", "Statement": statements}


SHARING_HELP = """What it is
Sharing lets people you trust use your server. They don't need an AWS account: they install Proxy on demand, choose "Join a friend's server" and paste your link. (Any Shadowsocks app, such as sing-box, NekoBox or Shadowrocket, can use the link too.)

Turning it on
Turn on the switch at the top of this page. While it's on, your server accepts connections from any network; the key inside the link is the only lock. Turning it off closes the server to everyone but your own network again.

The link
Press "Copy share link" and send it privately (not in public chats). It works only while your current server runs: after Stop, or when the server deletes itself, the next server gets a new address and a new link. Reconnect keeps the same server, so the link stays valid.

Who is connected
This page lists the devices connected right now, by IP address. Yours is marked "you". With one shared link, the server can't tell people apart by name. The limit is 5 devices at once, you included (two people on the same Wi-Fi count as one). If more connect, the app warns you: your link has probably been passed on, so press Stop and share a fresh link.

Removing people
Everyone uses the same key, so you can't remove just one person. To cut everyone off at once, turn sharing off (takes effect within seconds), or press Stop: the next server has a new key and address. Then share a fresh link only with the people you still want.

What it costs you
You pay for everything on your server: its running time and all data. Everyone shares your free 100 GB a month; when it's used up, the server stops for everyone. Bigger groups may need a bigger server size (Settings > Server).

Your responsibility
Their traffic leaves through your server and your AWS account, so you are responsible for it under AWS's Acceptable Use Policy (aws.amazon.com/aup). Share only with people you trust, never for illegal, abusive or unfair purposes, and cut people off if they misuse it.

For people who join
The server's owner can see your IP address and which sites you visit (not the content of encrypted pages). Only join servers of people you trust. Press Disconnect to leave."""

JOIN_INFO = ("You're connected through someone else's server with a link they shared.\n"
             "- The owner can see your IP address and which sites you visit (not the content of encrypted pages). "
             "Only join servers of people you trust.\n"
             "- The owner pays for your usage and is responsible for it, so use it fairly and legally.\n"
             "- The link works only while the owner's server runs. If it stops, ask them for a fresh link.")

JOIN_WARNING = ("Paste the share link someone sent you. Before you connect:\n"
                "- Only join servers of people you trust. The owner can see your IP address and which sites you "
                "visit (not the content of encrypted pages).\n"
                "- The owner pays for your usage and is responsible for it, so use it fairly and legally.\n"
                "- Press Disconnect to leave. The link stops working when the owner's server stops.")

SHARE_REMINDER = ("Share link copied.\n\n"
                  "- Send it privately to people you trust. Anyone with it can use your server while it runs.\n"
                  "- They paste it in Proxy on demand > Join a friend's server (or any Shadowsocks app).\n"
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
        self.budgets = session.client("budgets", region_name="us-east-1")  # Budgets and Free Tier: one endpoint
        self.freetier = session.client("freetier", region_name="us-east-1")
        self.sts = session.client("sts", region_name=self.region)
        self.log = log

    def app_budget(self):
        """AWS's own figure for this app this month: a free AWS Budgets budget limited to the app's tag, created
        on first use. AWS updates it up to 3 times a day; it counts once 'app' is an active cost allocation tag."""
        account = self.sts.get_caller_identity()["Account"]
        try:
            b = self.budgets.describe_budget(AccountId=account, BudgetName=BUDGET_NAME)["Budget"]
        except self.budgets.exceptions.NotFoundException:
            self.budgets.create_budget(AccountId=account, Budget={
                "BudgetName": BUDGET_NAME, "BudgetType": "COST", "TimeUnit": "MONTHLY",
                "BudgetLimit": {"Amount": "10", "Unit": "USD"},
                "CostFilters": {"TagKeyValue": [f"user:app${APP_TAG}"]},
                "CostTypes": {"IncludeCredit": False, "IncludeRefund": False}})  # the real cost, before credits
            self.log(f"Created the AWS Budgets budget '{BUDGET_NAME}' for this app's costs (free)")
            return {"actual": 0.0, "forecast": None}
        spend = b.get("CalculatedSpend", {})
        amount = lambda k: float(spend[k]["Amount"]) if k in spend else None
        return {"actual": amount("ActualSpend") or 0.0, "forecast": amount("ForecastedSpend")}

    def credits_left(self):
        """Credits left on the whole account's AWS free plan (accounts opened from 15 July 2025), or None."""
        c = self.freetier.get_account_plan_state().get("accountPlanRemainingCredits")
        return {"amount": float(c["amount"]), "unit": c["unit"]} if c else None

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
    return {"instances": ledger.get("instances", {}), "warned": ledger.get("warned", {}),
            "aws": ledger.get("aws", {})}


def save_ledger(ledger, path=None):
    os.makedirs(APP_DIR, exist_ok=True)
    write_json(path or USAGE_FILE, ledger)


def record_instance(iid, region, path=None, now=None, size=INSTANCE_TYPE, hours=MAX_HOURS):
    now = now or datetime.now(timezone.utc)
    ledger = load_ledger(path)
    keep_after = (now - timedelta(days=70)).isoformat()  # CloudWatch keeps hourly data for 63 days
    ledger["instances"] = {k: v for k, v in ledger["instances"].items() if v.get("launched", "") >= keep_after}
    ledger["instances"][iid] = {"region": region, "launched": now.isoformat(), "size": size, "hours": hours}
    save_ledger(ledger, path)


def run_window(info, now):
    """When a server ran: from launch to when it ended (Stop, or its auto-delete time at the latest)."""
    start = datetime.fromisoformat(info["launched"])
    latest = start + timedelta(hours=info.get("hours", MAX_HOURS))
    end = datetime.fromisoformat(info["ended"]) if info.get("ended") else latest
    return start, min(end, latest, now)


def close_finished_servers(region, live_ids, path=None, now=None):
    """Servers of this region that no longer exist get an end time, so the month's cost stops counting them."""
    now = now or datetime.now(timezone.utc)
    ledger, changed = load_ledger(path), False
    for iid, info in ledger["instances"].items():
        if info.get("region") == region and "launched" in info and "ended" not in info and iid not in live_ids:
            info["ended"] = run_window(info, now)[1].isoformat()
            changed = True
    if changed:
        save_ledger(ledger, path)


def month_cost(ledger, now, data_used=0, region=DEFAULT_SETTINGS["region"]):
    """What this app's servers cost this calendar month (UTC) at AWS list prices, before credits: each server's
    running time (server, public IP, disk; AWS bills them per second), plus data beyond the free 100 GB."""
    m0, total = month_start(now), 0.0
    for info in ledger["instances"].values():
        if "launched" not in info:
            continue
        start, end = run_window(info, now)
        hours = max(0.0, (end - max(start, m0)).total_seconds() / 3600)
        total += hours * hourly_usd(info.get("size", INSTANCE_TYPE), info.get("region", region))
    over_gb = max(0, (data_used or 0) - FREE_DATA_BYTES) / 2**30  # AWS bills data by the 2^30-byte GB
    return total + over_gb * rates(region)["data_gb"]


def gb(n_bytes):
    return f"{n_bytes / 10**9:.1f} GB"


AWS_EVERY = timedelta(hours=1)  # AWS updates budget figures a few times a day; reading them is free


def next_month(now):
    return (month_start(now) + timedelta(days=32)).replace(day=1)


def reset_text(now=None):
    """When the free 100 GB starts again: the 1st of next month, 00:00 UTC."""
    now = now or datetime.now(timezone.utc)
    reset = next_month(now)
    days = (reset - now).days
    return f"resets {reset.day} {reset:%b} ({'in under a day' if days < 1 else f'in {days} day' + ('s' if days > 1 else '')})"


def data_text(used, allow_over, now=None):
    if used is None:
        return ("Data this month: unknown. Your IAM policy needs updating: Settings > Copy IAM policy "
                "(Copy role permissions with MFA), and replace proxy-on-demand-ec2's JSON with it.")
    text = f"Data this month: {gb(used)} of the free 100 GB"
    text += (" (going over is allowed in Settings)" if allow_over else
             f", {gb(max(0, CAP_BYTES - used))} left")  # the plan card says the server stops itself at the cap
    return f"{text} · {reset_text(now)}"


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


def app_file(name):
    """A file shipped with the app (next to proxy_app.py, or inside the packaged exe)."""
    return os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))), name)


def load_prices(path=None):
    try:
        with open(path or app_file("prices.json"), encoding="utf-8") as f:
            data = json.load(f)
        return data["regions"], data.get("updated", "")
    except (OSError, ValueError, KeyError):
        return {}, ""


PRICES, PRICES_DATE = load_prices()


def rates(region=DEFAULT_SETTINGS["region"], size=INSTANCE_TYPE):
    """Per-hour cost of one server by part, at AWS's list prices for the region (prices.json; Mumbai if the
    region is missing). data_gb is per GB beyond the free 100 GB a month."""
    p = PRICES.get(region) or PRICES.get("ap-south-1") or \
        {"server": {k: v[0] for k, v in SERVER_SIZES.items()}, "ipv4_hour": 0.005, "gp3_gb_month": 0.0912,
         "data_out_gb": 0.1093}
    size = size if size in SERVER_SIZES else INSTANCE_TYPE
    return {"server": p["server"].get(size, SERVER_SIZES[size][0]), "ip": p["ipv4_hour"],
            "disk": p["gp3_gb_month"] * DISK_GB / 730, "data_gb": p["data_out_gb"]}


def hourly_usd(size=INSTANCE_TYPE, region=DEFAULT_SETTINGS["region"]):
    """Server + public IP + disk, per hour, at AWS's list price (data transfer not included)."""
    r = rates(region, size)
    return r["server"] + r["ip"] + r["disk"]


def plan_view(region, size, hours):
    """The cost breakdown for a session: what each part costs per hour, and the most a session can cost."""
    r, size = rates(region, size), size if size in SERVER_SIZES else INSTANCE_TYPE
    hourly = hourly_usd(size, region)
    return {"region": region, "region_name": REGION_NAMES.get(region, region), "size": size, "hours": hours,
            "parts": [[f"Server ({size})", r["server"]], ["Public IP address", r["ip"]],
                      [f"Disk ({DISK_GB} GB)", r["disk"]]],
            "hourly": hourly, "session_max": hourly * hours, "data_gb": r["data_gb"], "prices_date": PRICES_DATE}


def hours_text(h):
    return f"{int(h)}h {int(h * 60) % 60:02d}m"


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
REGIONS = ["ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "eu-west-1", "eu-west-2",
           "eu-central-1", "eu-north-1", "us-east-1", "us-east-2", "us-west-2", "ca-central-1", "sa-east-1",
           "me-central-1", "af-south-1"]  # common choices; any valid region code can be typed in
def windows_uses_dark():
    """Windows' 'app mode' setting (Settings > Personalization > Colors)."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as k:
            return winreg.QueryValueEx(k, "AppsUseLightTheme")[0] == 0
    except OSError:
        return False


def startup_mode(joined, tunnel_running):
    """'resume' when something is already running (show it), else 'choose' (ask own server or join)."""
    return "resume" if joined or tunnel_running else "choose"


def jsonable(o):
    """For sending to the page: sets become sorted lists, dates and the rest become text."""
    return sorted(o) if isinstance(o, (set, frozenset)) else str(o)


def denied(e):
    """Did AWS refuse because the IAM policy lacks a permission?"""
    code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
    return "AccessDenied" in code or "UnauthorizedOperation" in code or "AccessDenied" in str(e)


def device_name():
    """'This laptop' when Windows reports a battery, else 'This PC'."""
    class Power(ctypes.Structure):
        _fields_ = [("ac", ctypes.c_ubyte), ("flag", ctypes.c_ubyte), ("percent", ctypes.c_ubyte),
                    ("saver", ctypes.c_ubyte), ("life", ctypes.c_ulong), ("full", ctypes.c_ulong)]
    p = Power()
    try:
        ok = ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(p))
    except (AttributeError, OSError):
        ok = 0
    return "This laptop" if ok and not p.flag & 128 and p.flag != 255 else "This PC"


def tcp_ms(ip, port=None, timeout=3):
    """How long the server takes to accept a connection, in ms (None if it doesn't)."""
    if not ip:
        return None
    began = time.perf_counter()
    try:
        socket.create_connection((ip, port or PORT), timeout=timeout).close()
    except OSError:
        return None
    return round((time.perf_counter() - began) * 1000)


def sharing_view(info):
    """The Sharing page's data. info["state"]: off | on | joined, plus server/peers/mine while sharing."""
    view = {"state": info["state"], "server": bool(info.get("server")), "host": info.get("host"),
            "limit": SHARE_LIMIT, "peers": None}
    peers, mine = info.get("peers"), info.get("mine") or set()
    if peers is not None:
        view["peers"] = [{"ip": ip, "connections": n, "you": ip in mine}
                         for ip, n in sorted(peers.items(), key=lambda kv: (kv[0] not in mine, kv[0]))]
        view["over"] = len(peers) > SHARE_LIMIT
    return view


def set_clipboard(text):
    """Put text on the Windows clipboard (the page itself isn't allowed to)."""
    k32, u32 = ctypes.windll.kernel32, ctypes.windll.user32
    k32.GlobalAlloc.restype = k32.GlobalLock.restype = ctypes.c_void_p
    k32.GlobalLock.argtypes = k32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    u32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
    data = text.encode("utf-16-le") + b"\0\0"
    for _ in range(10):  # another app may hold the clipboard for a moment
        if u32.OpenClipboard(None):
            break
        time.sleep(0.05)
    else:
        raise RuntimeError("The clipboard is busy. Try again.")
    try:
        u32.EmptyClipboard()
        h = k32.GlobalAlloc(0x0002, len(data))  # GMEM_MOVEABLE
        ctypes.memmove(k32.GlobalLock(h), data, len(data))
        k32.GlobalUnlock(h)
        u32.SetClipboardData(13, h)  # CF_UNICODETEXT; Windows owns the memory now
    finally:
        u32.CloseClipboard()


def dark_title_bar(window, dark):
    """Match the window's title bar to the page's theme (Windows 10 2004+ / 11; silently skipped elsewhere)."""
    try:
        hwnd = window.native.Handle.ToInt32()
        on = ctypes.c_int(1 if dark else 0)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(on), ctypes.sizeof(on))
    except Exception:
        pass


def ui_html():
    """The page: ui/index.html with its stylesheet and script inlined. Loaded as a string, so no local web
    server runs and nothing else on this PC can talk to the app."""
    read = lambda n: open(app_file(os.path.join("ui", n)), encoding="utf-8").read()
    return read("index.html").replace("/*STYLE*/", read("style.css")).replace("/*SCRIPT*/", read("app.js"))


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
    """What the window shows and does. The page (ui/) only draws what this sends and calls Bridge."""
    server = None        # facts about the running server, for the route and the tiles
    check = {}           # the last connection check
    policy_missing = frozenset()  # read permissions the IAM policy lacks ("data", "bill")
    pending_mfa = None
    window = None
    ui_ready = closing_ok = False
    aws_figures_cache = None

    def __init__(self):
        self.q, self.busy, self.warp_was_on = queue.Queue(), False, False
        self.server_up, self.first_check = False, True
        self.session, self.session_expiry = None, None  # temporary AWS credentials, memory only
        self.connected_ip, self.health_failures, self.data_used, self.server_ip = None, 0, None, None
        self.over_limit_warned = None
        self.steps, self.step_index, self.step_started = None, 0, 0.0
        self.run_lock = threading.Lock()
        os.makedirs(APP_DIR, exist_ok=True)
        self.moved = migrate_old_files()
        self.joined = load_settings()["joined"] or None
        self.mode = "join" if self.joined else "own"

    # plumbing: events go to the page through the queue; timers are daemon threads

    def emit(self, kind, payload=None):
        self.q.put((kind, payload))

    def after(self, seconds, fn):
        t = threading.Timer(seconds, fn)
        t.daemon = True
        t.start()

    def send(self, events):
        try:
            self.window.run_js("window.ui && ui.receive(" + json.dumps(events, default=jsonable) + ")")
        except Exception:
            pass  # the window is closing

    def pump(self):
        """Forward queued events to the page, a few times a second, once the page is ready."""
        while not self.ui_ready:
            time.sleep(0.1)
        while True:
            events = []
            try:
                events.append(self.q.get(timeout=0.25))
                while True:
                    events.append(self.q.get_nowait())
            except queue.Empty:
                pass
            out = []
            for kind, msg in events:
                if kind == "done":
                    self.busy, self.steps = False, None
                elif kind == "restart":
                    self.after(0.5, self.restart)  # after "done" has reached the page
                    continue
                elif kind == "mfa":
                    self.pending_mfa, msg = msg, None
                out.append([kind, msg])
            if self.busy and self.steps:
                out.append(["progress", self.progress()])
            if out:
                self.send(out)

    def started(self):
        """The page has loaded: decide what to show first. Returns 'choose' or 'home'."""
        self.ui_ready = True
        if self.moved:
            self.log(f"Moved your saved {' and '.join(self.moved)} to {APP_DIR}")
        threading.Thread(target=self.check_for_update, daemon=True).start()
        self.after(300, self.tick)  # then poll_seconds() decides
        self.after(60, self.health)
        if startup_mode(self.joined, singbox_running()) == "resume":
            self.set_mode("join" if self.joined else "own")
            self.refresh()
            return "home"
        self.set_status("Welcome", "idle", "Run your own server, or join a server a friend shared with you.")
        return "choose"

    def snapshot(self):
        s = load_settings()
        return {"version": __version__, "mode": self.mode, "device": device_name(), "share_limit": SHARE_LIMIT,
                "settings": {k: s[k] for k in ("region", "size", "max_hours", "allow_over", "mfa", "sharing")},
                "plan": plan_view(s["region"], s["size"], s["max_hours"]), "route": self.route(),
                "texts": {"sharing_help": SHARING_HELP, "join_info": JOIN_INFO, "join_warning": JOIN_WARNING,
                          "share_reminder": SHARE_REMINDER, "agreement": list(AGREEMENT_POINTS)}}

    def choose(self, mode):
        self.set_mode(mode)
        if mode == "join":
            self.set_status("Not connected", "idle", "Paste the link your friend sent to connect.")
            return "home"
        if not load_key():
            self.set_status("Set up your AWS access", "idle", "Paste your AWS access key and choose a region, "
                                                              "then press Save. README Quick Start, step 5.")
            return "settings"
        self.refresh()
        return "home"

    def check_for_update(self):
        tag = newer_release()
        if tag:
            self.log(f"A new version ({tag}) is available: https://github.com/{REPO}/releases/latest")
            self.emit("update", {"tag": tag, "kind": update_kind()})

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
            self.emit("restart")
        self.run(job, UPDATE_STEPS, f"Updating to {tag}")

    def restart(self):
        if getattr(sys, "frozen", False):
            cmd = [sys.executable, "--after-update"]
        else:
            pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
            cmd = [pyw if os.path.exists(pyw) else sys.executable, os.path.join(app_folder(), "proxy_app.py"),
                   "--after-update"]
        subprocess.Popen(cmd, cwd=app_folder())
        self.close_window()

    def close_window(self):
        self.closing_ok = True
        if self.window:
            self.window.destroy()

    def show_sharing(self, info):
        self.emit("sharing", sharing_view(info))

    def copy_share_link(self):
        ip = self.connected_ip or self.server_ip
        if not (load_settings()["sharing"] and ip):
            return {"error": "Turn on sharing and start your server first."}
        set_clipboard(share_link(ip, ss_outbound(load_config()).get("password")))
        return {"ok": True}

    def join_link(self, link):
        if self.busy:
            return {"error": "Wait until the current step finishes."}
        if self.server_up:
            return {"error": "Your own server is running and billing. Stop it first, then join your friend's server."}
        try:
            parsed = parse_link(str(link))
        except ValueError as e:
            return {"error": str(e)}
        self.join(*parsed)
        return {"ok": True}

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
            self.emit("popup", f"Connected to your friend's server. Traffic now leaves through {ip}.")
        self.run(job, JOIN_STEPS, "Joining")

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
            self.check = {"at": time.time(), "tunnel": True, "server_ms": tcp_ms(self.joined), "exit_ok": True}
            self.set_status("Connected to a friend's server", "ok", "Their server, their bill. Press Disconnect "
                                                                    "to leave.")
            self.emit("sharing", sharing_view({"state": "joined", "host": self.joined}))
        else:
            self.leave_join()
            self.set_status("Disconnected from your friend's server", "warn",
                            "Their server stopped or they turned sharing off. Ask for a fresh link.")
            self.emit("sharing", sharing_view({"state": "on" if load_settings()["sharing"] else "off"}))
        self.emit("start_label", "Start")
        self.emit("route", self.route())

    def leave_join(self):
        stop_singbox()
        self.joined = self.connected_ip = None
        self.check = {}
        save_settings({"joined": ""})

    def set_mode(self, mode):
        """Show one screen: 'own' (run my own server) or 'join' (use a friend's server)."""
        self.mode = mode
        self.emit("mode", mode)
        self.emit("route", self.route())

    def switch_mode(self, confirmed=False):
        if self.busy:
            return {"error": "Wait until the current step finishes."}
        if self.mode == "own":
            if self.server_up:
                return {"error": "Your own server is running and billing. Stop it first, then switch to a "
                                 "friend's server."}
            self.set_mode("join")
            self.set_status("Not connected", "idle", "Paste the link your friend sent to connect.")
            return {"ok": True}
        if self.joined:
            if not confirmed:
                return {"confirm": "Disconnect from your friend's server?"}
            self.leave_join()
            self.log("Disconnected from your friend's server")
        self.set_mode("own")
        self.refresh()
        return {"ok": True}

    def toggle_sharing(self, on, agreed=False):
        if self.busy:  # never change the firewall in the middle of Start or Stop
            return {"error": "Wait until the current step finishes."}
        s = load_settings()
        if on and not (s["sharing_agreed"] or agreed):
            return {"agreement": list(AGREEMENT_POINTS)}
        save_settings({"sharing": on, **({"sharing_agreed": True} if agreed else {})})
        if self.server_up:
            self.log("Sharing " + ("turned on: opening" if on else "turned off: closing") + " the server's firewall")
            self.start()  # Reconnect: re-applies the firewall for the new setting
        else:
            self.show_sharing({"state": "on" if on else "off", "server": False})
        return {"ok": True}

    def update_cost(self):
        s = load_settings()
        self.emit("plan", plan_view(s["region"], s["size"], s["max_hours"]))

    def step(self, key):
        """Called from the worker thread: the job moved on to step `key`."""
        keys = [s[0] for s in self.steps or []]
        if key in keys:
            self.step_index, self.step_started = keys.index(key), time.time()
        self.emit("step", key)

    def progress(self):
        frac, left, late = progress_estimate(self.steps, self.step_index, time.time() - self.step_started)
        return {"frac": frac, "label": self.steps[self.step_index][1], "step": self.step_index + 1,
                "of": len(self.steps), "left": duration_text(left), "late": late}

    def log(self, msg):
        self.emit("log", time.strftime("%H:%M:%S ") + msg)
        try:
            with open(APP_LOG, "a", encoding="utf-8") as f:
                f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\n")
        except OSError:
            pass  # the on-screen log still works

    def set_status(self, msg, tone="idle", detail=""):
        self.emit("status", (msg, tone, detail))

    def run(self, job, steps, headline):
        with self.run_lock:
            if self.busy:
                return
            self.busy = True
        self.steps, self.step_index, self.step_started = steps, 0, time.time()
        self.set_status(headline, "busy", "")
        self.emit("busy", headline)

        def wrapped():
            try:
                job()
            except NoKeyError as e:
                self.log(str(e))
                self.set_status("Not set up yet", "idle",
                                "To run your own server, add your AWS key in Settings (README, Quick Start). "
                                "To use a friend's server, switch to Join a friend's server and paste their link.")
                self.emit("page", "settings")
            except SignInCancelled as e:
                self.log(str(e))
                self.set_status("Signed out", "warn", "Press Refresh to sign in with your MFA code.")
            except Exception as e:  # show every failure instead of dying silently
                self.log(f"ERROR: {e}")
                self.set_status("Something went wrong", "error", str(e))
                self.emit("warn", f"{e}\n\nFull log: {APP_LOG}")
            finally:
                self.emit("done")
                self.emit("route", self.route())
        threading.Thread(target=wrapped, daemon=True).start()

    def need_policy(self, what, ok):
        """Track which read permissions the IAM policy lacks; the page shows a banner until they work."""
        missing = (self.policy_missing - {what}) if ok else (self.policy_missing | {what})
        if missing != self.policy_missing:
            self.policy_missing = missing
            self.emit("policy", sorted(missing))

    def usage(self, aws, insts=()):
        """This month's data in bytes, or None if AWS won't say (old IAM policy without CloudWatch read).
        Running servers the ledger doesn't know (started by an older version) are added, so they count."""
        known = load_ledger()["instances"]
        for i in insts:
            if i["InstanceId"] not in known:
                record_instance(i["InstanceId"], aws.region, now=i["LaunchTime"],
                                size=i.get("InstanceType", INSTANCE_TYPE), hours=server_hours(i))
        try:
            used = aws.month_usage(load_ledger())
        except Exception as e:
            self.log(f"Could not read data usage from CloudWatch: {e}")
            if denied(e):
                self.need_policy("data", False)
            return None
        self.need_policy("data", True)
        return used

    def aws_figures(self, aws):
        """AWS's own figure for this app this month (a free AWS Budgets budget on the app's tag), and the credits
        left on the account. Both are free to read; still read at most once an hour, as AWS updates them only
        a few times a day."""
        ledger, now = load_ledger(), datetime.now(timezone.utc)
        cached = ledger.get("aws", {})
        if cached.get("month") == f"{now:%Y-%m}" and now - datetime.fromisoformat(cached["at"]) < AWS_EVERY:
            return cached
        figures = {"month": f"{now:%Y-%m}", "at": now.isoformat(), "budget": None, "credits": None}
        try:
            figures["budget"] = aws.app_budget()
            self.need_policy("bill", True)
        except Exception as e:
            self.log(f"Could not read this app's AWS Budgets figure: {e}")
            if denied(e):
                self.need_policy("bill", False)
        try:
            figures["credits"] = aws.credits_left()
        except Exception as e:  # e.g. accounts on the older free tier have no credit balance here
            self.log(f"Could not read your AWS credits: {e}")
        if figures["budget"] is not None:  # a failure isn't cached, so a fixed policy works at once
            ledger["aws"] = figures
            save_ledger(ledger)
        return figures

    def data_warnings(self, used, allow_over, server_gone):
        """Show each warning once a month: 80 %, 95 %, and when the server stopped itself at the limit."""
        ledger = load_ledger()
        month = datetime.now(timezone.utc).strftime("%Y-%m")
        warned = ledger["warned"].get(month, [])
        new = due_warnings(used, warned)
        capped = (server_gone and not allow_over and used is not None and used >= CAP_BYTES - 50 * 10**6
                  and "cap" not in warned)
        for t in new:
            self.emit("warn", (
                f"You've used {gb(used)} of this month's free 100 GB of data ({int(t * 100)} %). "
                + ("Going over is allowed in Settings, so your server keeps running and data beyond 100 GB is billed."
                   if allow_over else
                   f"At 99.99 GB your server stops itself, so data never costs you anything. {gb(max(0, CAP_BYTES - used))} left.")
                + " The free 100 GB is shared with anything else on your AWS account."))
        if capped:
            self.emit("warn", "Your server stopped itself: this month's free 100 GB of data is used up, so you weren't "
                              "charged for data. Start works again on the 1st (UTC), or allow going over in Settings.")
        if new or capped:
            ledger["warned"][month] = warned + new + (["cap"] if capped else [])
            save_ledger(ledger)
        return capped

    def tiles(self, insts, aws_fig, allow_over, region):
        """The numbers on the main screen: this session, this month, data, credits."""
        now = datetime.now(timezone.utc)
        session = None
        if insts:
            i = insts[0]
            size, hours = i.get("InstanceType", INSTANCE_TYPE), server_hours(i)
            ran = max(0.0, (now - i["LaunchTime"]).total_seconds() / 3600)
            rate = hourly_usd(size, region)
            session = {"usd": ran * rate, "hours": ran, "left_hours": max(0.0, hours - ran),
                       "max_usd": hours * rate, "rate": rate}
        budget = (aws_fig or {}).get("budget")
        return {
            "session": session,
            "month": {"usd": month_cost(load_ledger(), now, self.data_used or 0, region),
                      "aws": budget and budget.get("actual"), "forecast": budget and budget.get("forecast"),
                      "aws_at": (aws_fig or {}).get("at") if budget else None},
            "data": {"used": self.data_used, "cap": CAP_BYTES, "allow_over": allow_over, "reset": reset_text(now)},
            "credits": (aws_fig or {}).get("credits"),
        }

    def report(self, aws):
        insts = aws.instances()
        tunnel = singbox_running()
        self.server_up = bool(insts)
        settings = load_settings()
        allow_over, region = settings["allow_over"], aws.region
        self.data_used = self.usage(aws, insts)
        close_finished_servers(region, {i["InstanceId"] for i in insts})
        capped = self.data_warnings(self.data_used, allow_over, server_gone=not insts)
        self.server = None
        if insts:
            i = insts[0]
            ip = i.get("PublicIpAddress")
            self.server = {"ip": ip, "region": region, "size": i.get("InstanceType", INSTANCE_TYPE),
                           "launched": i["LaunchTime"], "hours": server_hours(i)}
            if tunnel and not self.connected_ip and ip:  # app was closed while connected: pick the connection up
                try:
                    if egress_ip() == ip:
                        self.connected_ip, self.health_failures = ip, 0
                        self.log(f"Picked up your existing connection through {ip}")
                except OSError:
                    pass
            if tunnel and self.connected_ip:
                self.set_status("Connected", "ok", "All your traffic leaves through your server. Changed network "
                                                   "(Wi-Fi to mobile data)? Press Reconnect.")
            else:
                self.set_status("Server running, but this device isn't connected", "warn",
                                "It's billing. Press Reconnect to use it, or Stop to delete it.")
            if self.first_check:  # e.g. the app crashed or was closed with "keep it running"
                self.emit("warn", "A proxy server is already running and billing. Press Reconnect to use it, or "
                                  "Stop if you aren't using it.")
        elif tunnel:  # e.g. the server auto-deleted while the app was closed: this tunnel only blocks traffic
            stop_singbox()
            self.connected_ip = None
            self.log("The tunnel was still running but its server is gone (it probably auto-deleted), "
                     "so the tunnel was stopped to restore your normal internet.")
            self.set_status("Not connected", "idle", "Your server had been deleted, so the leftover tunnel was "
                                                     "stopped. Nothing is billing.")
        else:
            self.connected_ip = None
            self.set_status("Not connected", "idle", "Nothing is running on AWS, so nothing is billing.")
        if capped:
            self.set_status("Stopped: this month's free 100 GB is used up", "warn",
                            "Your server stopped itself so you aren't charged for data. Start works again on the 1st "
                            "(UTC), or allow going over in Settings.")
        self.emit("tiles", self.tiles(insts, self.aws_figures(aws), allow_over, region))
        info = {"state": "on" if settings["sharing"] else "off", "server": bool(insts)}
        self.server_ip = insts[0].get("PublicIpAddress") if insts else None
        if insts and settings["sharing"] and self.server_ip:
            info.update(peers=server_peers(self.server_ip, tag(insts[0], "status-token")),
                        mine=aws.owner_ips(insts[0]))
            if info["peers"] and len(info["peers"]) > SHARE_LIMIT and self.over_limit_warned != self.server_ip:
                self.over_limit_warned = self.server_ip  # once per server
                self.emit("warn", f"{len(info['peers'])} devices are using your server, more than the limit of "
                                  f"{SHARE_LIMIT}. Your link has probably been passed on. You pay for all of them and "
                                  "are responsible for their traffic. Press Stop (the next server gets a new link), "
                                  "then share it only with people you trust.")
        self.show_sharing(info)
        self.emit("start_label", "Reconnect" if insts else "Start")
        if self.server_ip:  # every Refresh measures the ping, connected or not
            connected = bool(tunnel and self.connected_ip)
            self.check = {"at": time.time(), "tunnel": connected, "server_ms": tcp_ms(self.server_ip),
                          "exit_ok": connected}
        else:
            self.check = {}
        self.emit("route", self.route())
        self.first_check = False

    def route(self):
        """The three hops (this device, the server, the internet) with what is known about each right now."""
        c, tunnel = self.check, bool(self.check.get("tunnel")) or bool(self.connected_ip)
        name = device_name()
        if self.busy:
            device = {"name": name, "state": "busy", "lines": ["Working on it"]}
        elif tunnel:
            device = {"name": name, "state": "ok", "lines": ["Tunnel on", "DNS goes through the tunnel"]}
        else:
            device = {"name": name, "state": "idle", "lines": ["Tunnel off", "Your normal connection"]}
        ms = c.get("server_ms")
        if self.joined:
            server = {"name": "Friend's server", "state": "ok" if ms is not None else "error",
                      "lines": [self.joined, f"Ping {ms} ms" if ms is not None else "Not reachable from here"]}
        elif self.server:
            s = self.server
            left = max(0.0, s["hours"] - (datetime.now(timezone.utc) - s["launched"]).total_seconds() / 3600)
            reach = (f"ping {ms} ms" if ms is not None else
                     "Not reachable from this network" if c.get("at") else "Not checked yet")
            server = {"name": "Your server", "state": "error" if c.get("at") and ms is None else "ok",
                      "lines": [f"{REGION_NAMES.get(s['region'], s['region'])} · {s['size']}",
                                f"{s['ip'] or 'No IP yet'} · {reach}", f"Deletes itself in {hours_text(left)}"]}
        else:
            server = {"name": "Your server" if self.mode == "own" else "Friend's server", "state": "idle",
                      "lines": ["No server running" if self.mode == "own" else "Not connected",
                                "Nothing is billing" if self.mode == "own" else "Paste a link to connect"]}
        if self.connected_ip and c.get("exit_ok"):
            internet = {"name": "Internet", "state": "ok", "lines": ["Sites see the server's IP",
                                                                     f"Checked {time.strftime('%H:%M', time.localtime(c['at']))}"]}
        elif self.connected_ip:
            internet = {"name": "Internet", "state": "error", "lines": ["Traffic isn't getting through",
                                                                        "Press Reconnect"]}
        else:
            internet = {"name": "Internet", "state": "idle", "lines": ["Sites see your own IP", "Not protected"]}
        return {"device": device, "server": server, "internet": internet}

    def refresh(self):
        def job():
            if self.joined:
                return self.report_joined()
            if self.mode == "join":
                return self.set_status("Not connected", "idle", "Paste the link your friend sent to connect.")
            self.step("signin")
            aws = self.aws()
            self.step("check")
            self.report(aws)
        self.run(job, REFRESH_STEPS, "Checking")

    def health(self):
        """Every minute while connected: is the tunnel up, does the server answer, and does traffic really leave
        through it? Each hop on the route shows the result."""
        if (self.connected_ip or self.server_ip) and not self.busy:
            threading.Thread(target=self.check_now, daemon=True).start()
        self.after(60, self.health)

    def check_now(self):
        ip = self.connected_ip or self.server_ip
        ms, exit_ok = tcp_ms(ip), False
        if self.connected_ip:
            try:
                exit_ok = egress_ip() == self.connected_ip
            except OSError:
                pass
            self.health_failures = 0 if exit_ok else self.health_failures + 1
            if self.health_failures == 2:  # two misses in a row: tell the user once
                if self.joined:
                    self.log("Connection check failed twice: the shared server isn't reachable.")
                    self.set_status("Connection lost", "error", "The shared server stopped or its owner turned "
                                    "sharing off. Press Refresh, or ask for a fresh link.")
                else:
                    self.log("Connection check failed twice: the tunnel is not working. Press Reconnect.")
                    self.set_status("Connection lost", "error", "Your network probably changed. Press Reconnect "
                                    "(it reuses the server and just updates the allowed IPs), or Stop.")
        self.check = {"at": time.time(), "tunnel": singbox_running(), "server_ms": ms, "exit_ok": exit_ok}
        self.emit("route", self.route())

    def session_valid(self):
        if self.session is None:
            return False
        return self.session_expiry is None or \
            (self.session_expiry - datetime.now(timezone.utc)).total_seconds() > 300  # None: no-MFA key

    def ask_mfa(self):
        """Called from the worker thread: ask the page for an MFA code and wait for the answer."""
        done, box = threading.Event(), {}
        self.emit("mfa", (done, box))
        done.wait()
        return box.get("code")

    def mfa_code(self, code):
        if self.pending_mfa:
            done, box = self.pending_mfa
            self.pending_mfa = None
            box["code"] = code if code and re.fullmatch(r"\s*\d{6}\s*", str(code)) else None
            done.set()

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

    # settings page

    def settings_view(self):
        s, key = load_settings(), load_key()
        return {**{k: s[k] for k in ("region", "size", "max_hours", "allow_over", "mfa", "ssm_role")},
                "key_user": key["user_arn"].split("/")[-1] if key else None,
                "regions": [{"code": r, "name": REGION_NAMES.get(r, r)} for r in REGIONS],
                "sizes": [{"code": k, "label": v[1]} for k, v in SERVER_SIZES.items()],
                "max_hours_limit": MAX_HOURS_LIMIT}

    def save_settings_form(self, form, force=False):
        if self.busy:
            return {"error": "Wait until the current step finishes."}
        s = load_settings()
        r = str(form.get("region", "")).strip()
        if not valid_region(r):
            return {"error": "Enter a region code such as ap-south-1."}
        if r != s["region"] and self.server_up:  # would orphan a billing server in the old region
            return {"error": "Press Stop before changing the region, so the server in the current region is deleted."}
        mfa = bool(form.get("mfa"))
        size = form.get("size") if form.get("size") in SERVER_SIZES else INSTANCE_TYPE
        kid, sec_ = str(form.get("key_id", "")).strip(), str(form.get("secret", "")).strip()
        saved = load_key()
        if not (kid or sec_) and saved and mfa != s["mfa"]:
            kid, sec_ = saved["key_id"], saved["secret"]  # MFA switched: re-check the saved key
        if kid or sec_:
            try:
                record, warnings = inspect_key(kid, sec_, mfa, r)
            except Exception as e:
                return {"error": f"This key can't be used: {e}"}
            if warnings and not force:
                return {"warnings": warnings}
            save_key(record)
            self.log(f"AWS key saved, encrypted (user {record['user_arn'].split('/')[-1]})")
        save_settings({"mfa": mfa, "region": r, "ssm_role": str(form.get("ssm_role", "")).strip(),
                       "allow_over": bool(form.get("allow_over")), "max_hours": clamp_hours(form.get("max_hours")),
                       "size": size})
        self.session = None  # settings or key changed: sign in again
        self.update_cost()
        self.set_mode("own")
        self.refresh()  # signs in (with the MFA code if enabled) and proves the setup works
        return {"ok": True}

    def copy_policy(self, kind, form=None):
        """Put a policy on the clipboard and return the steps to use it. kind: user | role_permissions | trust |
        auto (whichever this setup needs: the IAM policy banner uses it)."""
        s, form = load_settings(), form or {}
        mfa = bool(form.get("mfa", s["mfa"]))
        region = str(form.get("region", s["region"])).strip()
        ssm_role = str(form.get("ssm_role", s["ssm_role"])).strip()
        if kind == "auto":
            kind = "role_permissions" if mfa else "user"
        if kind == "user" and mfa:
            text, guide = json.dumps(key_policy(), indent=2), "mfa_user"
        elif kind in ("user", "role_permissions"):
            if not valid_region(region):
                return {"error": "Enter a region code such as ap-south-1 first."}
            text, guide = json.dumps(iam_policy(region, ssm_role), indent=2), kind
        elif kind == "trust":
            try:
                kid, sec_ = str(form.get("key_id", "")).strip(), str(form.get("secret", "")).strip()
                record = inspect_key(kid, sec_)[0] if (kid or sec_) else load_key()
            except Exception as e:
                return {"error": str(e)}
            if not record:
                return {"error": "Enter the access key first: the trust policy names the user that owns it."}
            text, guide = json.dumps(trust_policy(record["user_arn"]), indent=2), "trust"
        else:
            return {"error": "Unknown policy."}
        set_clipboard(text)
        title, steps, anchor = COPY_GUIDES[guide]
        return {"title": title, "steps": steps.splitlines(), "anchor": anchor}

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
            began = time.time()
            try:
                if live:
                    self.log(f"Reusing running server {live[0]['InstanceId']}")
                    inst = aws.wait_running(live[0]["InstanceId"])
                else:
                    cap = self.data_allowance(aws)
                    launched = aws.launch(password, sg, subnet, hours, cap, size)
                    record_instance(launched, aws.region, size=size, hours=hours)  # counts even if it fails later
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
            server_h, rate = server_hours(inst), hourly_usd(inst.get("InstanceType", INSTANCE_TYPE), aws.region)
            self.emit("popup", f"Connected in {int(time.time() - began)} s. Your traffic now leaves through {got}. "
                               f"The server deletes itself after {server_h} h (at most {money(server_h * rate)}) "
                               "unless you press Stop first.")
        self.run(job, START_STEPS, "Reconnecting" if self.server_up else "Starting your server")

    def data_allowance(self, aws):
        """Bytes the new server may send before it stops itself (0 = no limit, the user allowed going over)."""
        if load_settings()["allow_over"]:
            self.log("No data limit on this server: going over the free 100 GB is allowed in Settings")
            return 0
        used = self.usage(aws)
        if used is None:
            raise RuntimeError(
                "The app can't read this month's data usage, so it can't promise the server stops before the free "
                "100 GB. Update your IAM policy (the banner at the top has the steps), or allow going over the "
                "free 100 GB in Settings.")
        left = CAP_BYTES - int(used)
        if left < 200 * 10**6:
            raise RuntimeError(
                f"This month's free 100 GB of data is used up ({gb(used)} so far), so Start is blocked to keep you "
                "from being charged. It resets on the 1st of next month (UTC). To start anyway, allow going over "
                "the free 100 GB in Settings.")
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
                self.emit("warn", f"These still exist and may bill: {', '.join(left)}. Press Stop again, or delete "
                                  f"them in the EC2 console ({aws.region}).")
            else:
                self.log("Verified: no proxy servers or disks left. Nothing is billing.")
                self.emit("popup", "Server deleted. Nothing is left billing.")
        self.run(job, STOP_STEPS, "Stopping")

    def tick(self):
        """While a server exists, refresh uptime, cost and data: every 15 min, every 5 min near the data limit.
        (The limit itself is enforced by the server every 5 seconds, even with the app closed.)"""
        if self.server_up and not self.busy:
            if self.session_valid():  # never ask for an MFA code from a background timer
                self.refresh()
            else:
                self.set_status("Signed out (the 1-hour sign-in ended)", "warn",
                                "Your server may still be running and billing. Press Refresh to sign in "
                                "and check, or Stop to end it. Its data limit still applies.")
        self.after(poll_seconds(self.data_used, load_settings()["allow_over"]), self.tick)

    def on_closing(self):
        """The window's close button. Returning False keeps it open and asks on the page instead."""
        if self.closing_ok:
            return True
        if self.busy:
            self.emit("quit", {"busy": True})
            return False
        if not self.server_up and not singbox_running():
            return True
        self.emit("quit", {"busy": False, "server": self.server_up,
                           "sharing": bool(load_settings()["sharing"] and self.server_up)})
        return False

    def quit(self, choice):
        if choice == "stop":
            self.stop()
            self.close_when_idle()
        elif choice in ("keep", "force"):
            self.close_window()

    def close_when_idle(self):
        if self.busy:
            self.after(0.5, self.close_when_idle)
        else:
            self.close_window()


class Bridge:
    """The only things the page can call. pywebview exposes this object's public methods to the page's
    JavaScript (never names starting with _), so the App itself stays out of reach."""
    MODES, SCREENS = ("own", "join"), ("own", "join")
    LINKS = {"aws_console": "https://console.aws.amazon.com/",
             "cost_tags": "https://us-east-1.console.aws.amazon.com/billing/home#/tags",
             "budgets": "https://us-east-1.console.aws.amazon.com/billing/home#/budgets",
             "credits": "https://us-east-1.console.aws.amazon.com/billing/home#/credits",
             "releases": f"https://github.com/{REPO}/releases/latest"}

    def __init__(self, app):
        self._app = app

    def ready(self):
        return {**self._app.snapshot(), "screen": self._app.started()}

    def choose(self, mode):
        return self._app.choose(mode) if mode in self.MODES else "choose"

    def start(self):
        self._app.start()

    def stop(self):
        self._app.stop()

    def refresh(self):
        self._app.refresh()

    def switch_mode(self, confirmed=False):
        return self._app.switch_mode(bool(confirmed))

    def join(self, link):
        return self._app.join_link(link)

    def set_sharing(self, on, agreed=False):
        return self._app.toggle_sharing(bool(on), bool(agreed))

    def copy_share_link(self):
        return self._app.copy_share_link()

    def settings(self):
        return self._app.settings_view()

    def estimate(self, region, size, hours):
        return plan_view(str(region), str(size), clamp_hours(hours))

    def save_settings(self, form, force=False):
        return self._app.save_settings_form(form if isinstance(form, dict) else {}, bool(force))

    def copy_policy(self, kind, form=None):
        return self._app.copy_policy(str(kind), form if isinstance(form, dict) else None)

    def mfa_code(self, code=None):
        self._app.mfa_code(code)

    def update_now(self, tag):
        if isinstance(tag, str) and re.fullmatch(r"v?\d+\.\d+\.\d+", tag) and update_kind() != "git":
            self._app.update_to(tag, update_kind())

    def quit(self, choice):
        self._app.quit(str(choice))

    def open_logs(self):
        os.startfile(APP_DIR)

    def open_guide(self, anchor):
        if isinstance(anchor, str) and re.fullmatch(r"[a-z0-9-]{1,80}", anchor):
            webbrowser.open(f"https://github.com/{REPO}#{anchor}")

    def open_link(self, name):
        if name in self.LINKS:
            webbrowser.open(self.LINKS[name])

    def set_dark(self, dark):
        dark_title_bar(self._app.window, bool(dark))


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
    """`--check`: prove a build or install is complete without touching AWS or the network. Exit code 0 = OK."""
    import boto3  # bundled?
    import webview  # noqa: F401  the window
    boto3.session.Session().get_available_regions("ec2")  # botocore data files bundled?
    assert _dpapi(_dpapi(b"x", protect=True), protect=False) == b"x"
    assert "SS-SETUP-DONE" in user_data("x") and iam_policy("ap-south-1")["Statement"]
    assert PRICES and all(r in PRICES for r in REGIONS), "prices.json missing or incomplete"
    assert "ui.receive" in ui_html(), "ui/ files missing"
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


def bring_to_front():
    """Another copy is open: show its window instead of opening a second one."""
    u32, found = ctypes.windll.user32, []
    proto = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

    def visit(hwnd, _):
        buf = ctypes.create_unicode_buffer(256)
        u32.GetWindowTextW(hwnd, buf, 256)
        if buf.value.startswith("Proxy on demand"):
            found.append(hwnd)
        return True
    u32.EnumWindows(proto(visit), 0)
    for hwnd in found[:1]:
        u32.ShowWindow(hwnd, 9)  # SW_RESTORE
        u32.SetForegroundWindow(hwnd)


def main():
    import webview
    app = App()
    dark = windows_uses_dark()
    window = webview.create_window(f"Proxy on demand {__version__}", html=ui_html(), js_api=Bridge(app),
                                   width=1080, height=780, min_size=(860, 640),
                                   background_color="#0e0e10" if dark else "#f4f4f5")
    app.window = window
    window.events.closing += app.on_closing
    window.events.shown += lambda: dark_title_bar(window, dark)
    threading.Thread(target=app.pump, daemon=True).start()
    webview.start(gui="edgechromium", private_mode=True, storage_path=os.path.join(APP_DIR, "webview"))


if __name__ == "__main__":
    if "--version" in sys.argv:
        print(__version__)
        sys.exit(0)
    if "--check" in sys.argv:
        sys.exit(self_check())
    ensure_admin()
    remove_old_exe()
    if already_running(wait=20 if "--after-update" in sys.argv else 0):
        bring_to_front()
        sys.exit(0)
    main()
