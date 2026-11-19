"""Offline checks for proxy_app (no AWS calls). Run: python test_proxy_app.py"""
import json
import os
import shutil
import subprocess
import tempfile

import proxy_app as app

# set_server changes only ss-out.server, keeps a backup, writes no BOM
d = tempfile.mkdtemp()
cfg = os.path.join(d, "config.json")
with open(cfg, "w", encoding="utf-8-sig") as f:  # start WITH a BOM to check it is dropped
    json.dump({"outbounds": [{"tag": "ss-out", "server": "1.1.1.1", "password": "pw"}], "x": 1}, f)
app.set_server("9.9.9.9", cfg)
raw = open(cfg, "rb").read()
assert not raw.startswith(b"\xef\xbb\xbf"), "BOM written"
new = json.loads(raw)
assert new["outbounds"][0]["server"] == "9.9.9.9" and new["outbounds"][0]["password"] == "pw" and new["x"] == 1
assert json.load(open(cfg + ".app-backup", encoding="utf-8-sig"))["outbounds"][0]["server"] == "1.1.1.1"
app.set_server("8.8.8.8", cfg)  # second run must not overwrite the original backup
assert json.load(open(cfg + ".app-backup", encoding="utf-8-sig"))["outbounds"][0]["server"] == "1.1.1.1"
shutil.rmtree(d)

# user_data: valid bash, password only inside the quoted heredoc
ud = app.user_data("SECRET+/=")
assert ud.count("SECRET+/=") == 1 and "<<'EOF'\n{" in ud
bash = shutil.which("bash") or r"C:\Program Files\Git\bin\bash.exe"
r = subprocess.run([bash, "-n"], input=ud.encode(), capture_output=True)
assert r.returncode == 0, r.stderr
# allow_only: removes the open 0.0.0.0/0 rules, leaves only ip/32, and is a no-op when already right
class FakeEc2:
    def __init__(self, perms): self.perms, self.calls = perms, []
    def describe_security_groups(self, GroupIds): return {"SecurityGroups": [{"IpPermissions": self.perms}]}
    def revoke_security_group_ingress(self, GroupId, IpPermissions): self.calls.append("revoke"); self.perms = []
    def authorize_security_group_ingress(self, GroupId, IpPermissions): self.calls.append("auth"); self.perms = IpPermissions

aws = app.Aws.__new__(app.Aws)
aws.log = lambda m: None
aws.ec2 = FakeEc2([{"IpProtocol": p, "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                   for p in ("tcp", "udp")])
aws.allow_only("sg-1", "1.2.3.4")
assert aws.ec2.calls == ["revoke", "auth"]
assert sorted(r["IpProtocol"] for r in aws.ec2.perms) == ["tcp", "udp"]
assert all(r["IpRanges"][0]["CidrIp"] == "1.2.3.4/32" and len(r["IpRanges"]) == 1 for r in aws.ec2.perms)
aws.ec2.calls = []
aws.allow_only("sg-1", "1.2.3.4")
assert aws.ec2.calls == [], "should not touch rules that are already correct"
# ensure_config: creates a valid config with a 16-byte base64 key, never overwrites an existing one
import base64
d = tempfile.mkdtemp()
cfg = os.path.join(d, "sub", "config.json")
assert app.ensure_config(cfg) is True
pw = app.ss_outbound(app.load_config(cfg))["password"]
assert len(base64.b64decode(pw)) == 16
assert app.ensure_config(cfg) is False and app.ss_outbound(app.load_config(cfg))["password"] == pw
app.set_server("9.9.9.9", cfg)
# real validation when sing-box is available (set SINGBOX_EXE to point at one); skipped in CI
exe = os.environ.get("SINGBOX_EXE") or app.find_singbox()
if exe:
    r = subprocess.run([exe, "check", "-c", cfg], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
shutil.rmtree(d)

# Settings, key storage, policy
d = tempfile.mkdtemp()
sf = os.path.join(d, "s", "settings.json")
assert app.load_settings(sf) == app.DEFAULT_SETTINGS  # missing file -> defaults
app.save_settings({"region": "eu-west-1", "ssm_role": "R"}, sf)
assert app.load_settings(sf) == {"region": "eu-west-1", "ssm_role": "R"}
open(sf, "w").write("{broken")
assert app.load_settings(sf) == app.DEFAULT_SETTINGS  # corrupt file -> defaults, no crash

assert app.valid_region("ap-south-1") and app.valid_region("us-gov-west-1")
assert not app.valid_region("Mumbai") and not app.valid_region("ap-south-1; rm")

GOOD_ID, GOOD_SECRET = "AKIA" + "A" * 16, "a" * 39 + "/"  # fake, correctly shaped
for bad in [("ASIA" + "A" * 16, GOOD_SECRET), ("AKIA123", GOOD_SECRET), (GOOD_ID, "short"), (GOOD_ID, "a" * 39 + " ")]:
    try:
        app.validate_key(*bad); raise AssertionError(f"accepted bad key {bad[0][:6]}")
    except ValueError:
        pass
cred = os.path.join(d, ".aws", "credentials")
os.makedirs(os.path.dirname(cred))
open(cred, "w").write("[default]\naws_access_key_id = OTHER\n")
app.save_key(GOOD_ID, GOOD_SECRET, cred)
import configparser
cp = configparser.RawConfigParser(); cp.read(cred)
assert cp["default"]["aws_access_key_id"] == "OTHER", "other profiles must be kept"
assert cp[app.PROFILE]["aws_access_key_id"] == GOOD_ID and cp[app.PROFILE]["aws_secret_access_key"] == GOOD_SECRET
shutil.rmtree(d)

here = os.path.dirname(os.path.abspath(__file__))
assert json.load(open(os.path.join(here, "iam-policy.json"))) == app.iam_policy("ap-south-1"), \
    "iam-policy.json is out of date: regenerate it from iam_policy()"
p = app.iam_policy("eu-west-1", "MyRole")
text = json.dumps(p)
assert "ap-south-1" not in text and "eu-west-1" in text and "role/MyRole" in text
assert "iam:PassRole" not in json.dumps(app.iam_policy("eu-west-1")), "no role -> no IAM permission at all"

# install_singbox: rejects a wrong checksum; never writes outside its folder
import io, hashlib, zipfile
real_urlopen, real_home, real_sha = app.urllib.request.urlopen, app.SB_HOME, app.SB_ZIP_SHA256
class Resp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): pass
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    z.writestr("sing-box-x/sing-box.exe", b"exe")
    z.writestr("../../evil.txt", b"x")
data = buf.getvalue()
d = tempfile.mkdtemp()
app.SB_HOME = os.path.join(d, "home")
app.urllib.request.urlopen = lambda *a, **k: Resp(data)
try:
    app.install_singbox(lambda m: None); raise AssertionError("bad checksum accepted")
except RuntimeError:
    pass
assert not os.path.exists(app.SB_HOME), "nothing may be written when the checksum fails"
app.SB_ZIP_SHA256 = hashlib.sha256(data).hexdigest()
exe_path = app.install_singbox(lambda m: None)
assert open(exe_path, "rb").read() == b"exe"
assert sorted(os.listdir(app.SB_HOME)) == ["evil.txt", "sing-box.exe"]
assert not os.path.exists(os.path.join(d, "evil.txt")) and not os.path.exists(os.path.join(os.path.dirname(d), "evil.txt"))
app.urllib.request.urlopen, app.SB_HOME, app.SB_ZIP_SHA256 = real_urlopen, real_home, real_sha
shutil.rmtree(d)

# warp_connected: "Disconnected" must not count as connected
real_warp = app.warp
app.warp = lambda *a: "Status update: Disconnected\nReason: Manual"
assert app.warp_connected() is False
app.warp = lambda *a: "Status update: Connected\nNetwork: healthy"
assert app.warp_connected() is True
app.warp = lambda *a: ""  # WARP not installed
assert app.warp_connected() is False
app.warp = real_warp

# uptime_text: cost and countdown
from datetime import datetime, timedelta, timezone
now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
t = app.uptime_text(now - timedelta(hours=2, minutes=5), now)
assert t.startswith("up 2h05m") and "auto-terminates in 9h55m" in t, t
assert "in 0h00m" in app.uptime_text(now - timedelta(hours=30), now)


# Billing fail-safes, with AWS and the local network faked out
import queue
class FakeAws:
    def __init__(self, insts=(), fail_wait_port=False):
        self.insts, self.terminated, self.launched = list(insts), [], []
        self.log = lambda m: None
    def default_vpc_subnet(self): return "vpc-1", "subnet-1"
    def security_group(self, vpc): return "sg-1"
    def allow_only(self, sg, ip): pass
    def instances(self): return [i for i in self.insts if i["InstanceId"] not in self.terminated]
    def launch(self, pw, sg, subnet):
        self.launched.append("i-new")
        self.insts.append({"InstanceId": "i-new", "State": {"Name": "pending"}, "LaunchTime": now})
        return "i-new"
    def wait_running(self, iid): return {"InstanceId": iid, "PublicIpAddress": "5.6.7.8", "LaunchTime": now}
    def terminate(self, ids): self.terminated += ids
    def leftovers(self): return [i["InstanceId"] for i in self.instances()]
    def terminate_all(self):
        ids = [i["InstanceId"] for i in self.instances()]
        self.terminate(ids)
        return self.leftovers()

def fake_app(aws):
    a = app.App.__new__(app.App)
    a.q, a.busy, a.warp_was_on, a.server_up, a.first_check = queue.Queue(), False, False, False, False
    a.log = lambda m: None
    a.run = lambda job: job()  # synchronous, exceptions propagate
    for name, fn in {"Aws": lambda *a: aws, "find_singbox": lambda: "sing-box.exe", "ensure_config": lambda: False,
                     "load_config": lambda: {"outbounds": [{"tag": "ss-out", "password": "pw"}]},
                     "warp_connected": lambda: False, "stop_singbox": lambda: None, "my_ip": lambda: "1.2.3.4",
                     "singbox_running": lambda: False, "set_server": lambda ip: None,
                     "start_singbox": lambda exe: None, "egress_ip": lambda: "5.6.7.8"}.items():
        setattr(app, name, fn)
    return a

def kinds(a):
    out = []
    while not a.q.empty():
        out.append(a.q.get())
    return out

def boom(*a): raise RuntimeError("port never opened")

# 1. Start fails after launching -> the new server is terminated
aws = FakeAws()
a = fake_app(aws)
app.wait_port = boom
try:
    a.start(); raise AssertionError("start should have failed")
except RuntimeError as e:
    assert "port never opened" in str(e)
assert aws.launched == ["i-new"] and aws.terminated == ["i-new"], aws.terminated

# 2. Start fails on a REUSED server -> it is not terminated (the user started it earlier)
aws = FakeAws([{"InstanceId": "i-old", "State": {"Name": "running"}, "LaunchTime": now}])
a = fake_app(aws)
try:
    a.start()
except RuntimeError:
    pass
assert aws.launched == [] and aws.terminated == []

# 3. Stopped servers are cleaned up, and a working Start shows the success popup
app.wait_port = lambda ip, log: None
aws = FakeAws([{"InstanceId": "i-stopped", "State": {"Name": "stopped"}, "LaunchTime": now}])
a = fake_app(aws)
a.start()
assert aws.terminated == ["i-stopped"] and aws.launched == ["i-new"]
assert any(k == "popup" and "Successfully connected" in m for k, m in kinds(a))

# 4. Stop verifies nothing is left; a leftover raises a warning
a.stop()
assert aws.instances() == [] and not any(k == "warn" for k, m in kinds(a))
aws.leftovers = lambda: ["vol-123"]
a.stop()
assert any(k == "warn" and "vol-123" in m for k, m in kinds(a))

# 5. A server already running when the app opens triggers a warning
aws = FakeAws([{"InstanceId": "i-old", "State": {"Name": "running"}, "LaunchTime": now}])
a = fake_app(aws)
a.first_check = True
a.report(aws)
assert a.server_up and any(k == "warn" and "already running" in m for k, m in kinds(a))

# safety net is scheduled before anything that could fail
ud = app.user_data("x")
assert ud.index("shutdown -h +") < ud.index("curl ")
print("all checks passed" + ("" if exe else " (sing-box check skipped)"))
