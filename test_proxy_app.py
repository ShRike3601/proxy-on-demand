"""Offline checks for proxy_app (no AWS calls). Run: python test_proxy_app.py"""
import json
import os
import shutil
import subprocess
import tempfile

import proxy_app as app
REAL = {n: getattr(app, n) for n in ("record_instance", "load_ledger", "save_ledger")}  # before fakes replace them

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
aws.allow_only("sg-1", {"1.2.3.4"})
assert aws.ec2.calls == ["revoke", "auth"]
assert sorted(r["IpProtocol"] for r in aws.ec2.perms) == ["tcp", "udp"]
assert all(r["IpRanges"][0]["CidrIp"] == "1.2.3.4/32" and len(r["IpRanges"]) == 1 for r in aws.ec2.perms)
aws.ec2.calls = []
aws.allow_only("sg-1", {"1.2.3.4"})
assert aws.ec2.calls == [], "should not touch rules that are already correct"
aws.allow_only("sg-1", {"1.2.3.4", "5.6.7.8"})  # a network with two public IPs: both allowed, nothing else
assert aws.ec2.calls == ["revoke", "auth"]
assert all(sorted(x["CidrIp"] for x in r["IpRanges"]) == ["1.2.3.4/32", "5.6.7.8/32"] for r in aws.ec2.perms)

# my_ips: collects every IPv4 the network shows, ignores junk and failures
import itertools
real_urlopen = app.urllib.request.urlopen
class R:
    def __init__(self, b): self.b = b
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def read(self): return self.b
replies = itertools.cycle([b"103.0.0.1\n", b"123.0.0.2", b"2001:db8::1", OSError("down"), b"<html>"])
def fake_open(url, timeout):
    x = next(replies)
    if isinstance(x, Exception): raise x
    return R(x)
app.urllib.request.urlopen = fake_open
assert app.my_ips() == {"103.0.0.1", "123.0.0.2"}
app.urllib.request.urlopen = lambda *a, **k: (_ for _ in ()).throw(OSError("offline"))
try:
    app.my_ips(); raise AssertionError("no IP found must be an error")
except RuntimeError:
    pass
app.urllib.request.urlopen = real_urlopen

# wait_port: re-checks the allowed IPs every 30 s while waiting, gives up after the timeout
clock = [0.0]
real_time, real_sleep, real_conn = app.time.time, app.time.sleep, app.socket.create_connection
app.time.time = lambda: clock[0]
app.time.sleep = lambda s: clock.__setitem__(0, clock[0] + s)
app.socket.create_connection = lambda *a: (_ for _ in ()).throw(OSError("refused"))
rechecks = []
try:
    app.wait_port("9.9.9.9", lambda m: None, lambda: rechecks.append(clock[0]), timeout=120)
    raise AssertionError("closed port must time out")
except RuntimeError:
    pass
assert 3 <= len(rechecks) <= 4, rechecks
app.time.time, app.time.sleep, app.socket.create_connection = real_time, real_sleep, real_conn

# migrate_old_files: copies key and settings once, never overwrites newer files
d = tempfile.mkdtemp()
old, new = os.path.join(d, "old"), os.path.join(d, "new")
os.makedirs(old)
open(os.path.join(old, "aws-key.bin"), "w").write("K")
open(os.path.join(old, "settings.json"), "w").write("S")
assert app.migrate_old_files(old, new) == ["aws-key.bin", "settings.json"]
open(os.path.join(new, "settings.json"), "w").write("NEWER")
assert app.migrate_old_files(old, new) == [] and open(os.path.join(new, "settings.json")).read() == "NEWER"
shutil.rmtree(d)
assert "AppData" not in app.APP_DIR and "AppData" not in app.SB_CONFIG, "Store Python would redirect these"
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
assert app.DEFAULT_SETTINGS["mfa"] is False, "MFA is an opt-in extra (Settings > Advanced)"
app.save_settings({"region": "eu-west-1", "ssm_role": "R"}, sf)  # file from before the MFA option existed
assert app.load_settings(sf) == {"mfa": False, "region": "eu-west-1", "ssm_role": "R", "max_hours": 12, "allow_over": False,
                                    "size": "t3.micro", "theme": "system"}
app.save_settings({"mfa": False, "region": "eu-west-1", "ssm_role": ""}, sf)
assert app.load_settings(sf)["mfa"] is False
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
# Encrypted key store: round-trips, never holds the secret in plain text, fails safely
keyf = os.path.join(d, "app", "aws-key.bin")
assert app.load_key(keyf) is None  # nothing saved yet
cred = os.path.join(d, ".aws", "credentials")
os.makedirs(os.path.dirname(cred))
open(cred, "w").write(f"[default]\naws_access_key_id = OTHER\n\n[{app.OLD_PROFILE}]\naws_access_key_id = OLD\n")
real_plain = app.PLAINTEXT_CRED_FILE
app.remove_plaintext_profile.__defaults__ = (cred,)
record = {"key_id": GOOD_ID, "secret": GOOD_SECRET, "mfa_serial": "arn:aws:iam::1:mfa/x",
          "role_arn": "arn:aws:iam::1:role/r", "user_arn": "arn:aws:iam::1:user/u"}
app.save_key(record, keyf)
raw = open(keyf, "rb").read()
assert GOOD_SECRET.encode() not in raw and GOOD_ID.encode() not in raw, "key must not be stored in plain text"
assert app.load_key(keyf) == record
open(keyf, "wb").write(raw[:-5] + b"xxxxx")  # tampered / copied-from-elsewhere file
try:
    app.load_key(keyf); raise AssertionError("tampered key file accepted")
except RuntimeError:
    pass
import configparser
cp = configparser.RawConfigParser(); cp.read(cred)
assert cp.sections() == ["default"], "only the old plain-text profile of this app is removed"
app.remove_plaintext_profile.__defaults__ = (real_plain,)
try:
    app.save_key({**record, "secret": "short"}, keyf); raise AssertionError("invalid key saved")
except ValueError:
    pass
shutil.rmtree(d)

# Policies: repo files match the code; the key alone can do nothing but assume the role
here = os.path.dirname(os.path.abspath(__file__))
pol = lambda name: json.load(open(os.path.join(here, "policies", name)))
assert pol("role-permissions.json") == app.iam_policy("ap-south-1"), "regenerate policies/ from the code"
assert pol("key-policy.json") == app.key_policy(), "regenerate policies/ from the code"
kp = json.dumps(app.key_policy())
assert "ec2:" not in kp and "iam:PassRole" not in kp and "sts:AssumeRole" in kp
assert f"role/{app.ROLE_NAME}" in kp
tp = app.trust_policy("arn:aws:iam::1:user/u")["Statement"][0]
assert tp["Principal"] == {"AWS": "arn:aws:iam::1:user/u"}, "trust only the one user, not the whole account"
assert tp["Condition"]["Bool"]["aws:MultiFactorAuthPresent"] == "true"
assert int(tp["Condition"]["NumericLessThan"]["aws:MultiFactorAuthAge"]) <= 3600
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
t = app.uptime_text(now - timedelta(hours=2, minutes=5), now=now)
assert t.startswith("Running 2h05m") and "auto-deletes in 9h55m" in t and "at most ~$0.21" in t, t
assert "in 0h00m" in app.uptime_text(now - timedelta(hours=30), now=now)
t = app.uptime_text(now - timedelta(minutes=10), 3, now=now)
assert "auto-deletes in 2h50m" in t and "at most ~$0.05" in t and "less than $0.01" in t, t
t = app.uptime_text(now - timedelta(hours=1), 12, now=now, size="t3.medium")
assert "cost so far ~$0.05" in t and "at most ~$0.61" in t, "a bigger server costs more"

# cost_text and sizes: hourly rate and session maximum per size; policy allows exactly the offered sizes
assert "t3.micro, about $0.017 per hour" in app.cost_text(12) and "at most about $0.21" in app.cost_text(12)
assert "at most about $0.02" in app.cost_text(1)
assert "t3.small, about $0.028 per hour" in app.cost_text(12, "t3.small")
assert app.hourly_usd("t3.medium") > app.hourly_usd("t3.small") > app.hourly_usd("t3.micro")
assert app.hourly_usd("bogus") == app.hourly_usd("t3.micro")
launch_rule = next(s for s in app.iam_policy("ap-south-1")["Statement"] if s["Sid"] == "LaunchOnlyTaggedSmallServers")
assert launch_rule["Condition"]["StringEquals"]["ec2:InstanceType"] == list(app.SERVER_SIZES)
assert all(not k.startswith(("t4g", "c7g", "m7g")) for k in app.SERVER_SIZES), "x86 only (x86 Shadowsocks build)"

# settings: unknown size/theme fall back to defaults; theme choice resolves to light or dark
d = tempfile.mkdtemp()
sf = os.path.join(d, "settings.json")
open(sf, "w").write(json.dumps({"size": "x9.huge", "theme": "neon"}))
assert app.load_settings(sf)["size"] == "t3.micro" and app.load_settings(sf)["theme"] == "system"
shutil.rmtree(d)
assert app.resolve_theme("dark") == "dark" and app.resolve_theme("light") == "light"
assert app.resolve_theme("system") in ("light", "dark")
assert set(app.THEMES["light"]) == set(app.THEMES["dark"]), "both themes define every color"

# auto-delete hours: clamped to 1..24, carried into the server script and read back from the tag
assert [app.clamp_hours(x) for x in (0, 1, "5", 99, "junk", None)] == [1, 1, 5, 24, 12, 12]
assert "shutdown -h +180\n" in app.user_data("x", 3) and "shutdown -h +1440\n" in app.user_data("x", 500)
assert app.server_hours({"Tags": [{"Key": "auto-delete-hours", "Value": "6"}]}) == 6
assert app.server_hours({}) == app.MAX_HOURS  # servers launched before the setting existed
d = tempfile.mkdtemp()
sf = os.path.join(d, "settings.json")
app.save_settings({"region": "eu-west-1"}, sf)
app.save_settings({"max_hours": 6}, sf)  # saving one setting keeps the others
assert app.load_settings(sf)["region"] == "eu-west-1" and app.load_settings(sf)["max_hours"] == 6
shutil.rmtree(d)

# progress_estimate: moves with time, never finishes early, flags a slow step
steps = [("a", "A", 10), ("b", "B", 30)]
f0, left0, late0 = app.progress_estimate(steps, 0, 0)
f1, left1, late1 = app.progress_estimate(steps, 0, 5)
f2, left2, late2 = app.progress_estimate(steps, 0, 100)  # step a is very late
f3, left3, _ = app.progress_estimate(steps, 1, 0)
assert f0 == 0 and left0 == 40 and not late0
assert 0 < f1 < f2 < f3 < 1 and left1 == 35
assert late2 and f2 < 10 / 40, "a slow step must not push the bar past its share"
assert app.progress_estimate(steps, 1, 1000)[0] < 1
assert app.duration_text(45) == "45 s" and app.duration_text(95) == "1 min 35 s"
step_keys = lambda steps: [s[0] for s in steps]
for steps in (app.START_STEPS, app.STOP_STEPS, app.REFRESH_STEPS):
    assert len(set(step_keys(steps))) == len(steps) and all(s[2] > 0 for s in steps)
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy_app.py"), encoding="utf-8").read()
for key in step_keys(app.START_STEPS) + step_keys(app.STOP_STEPS):
    assert f'self.step("{key}")' in src, f"step {key} is never reported, so the bar would stall"


# Billing fail-safes, with AWS and the local network faked out
import queue
class FakeAws:
    def __init__(self, insts=(), fail_wait_port=False):
        self.insts, self.terminated, self.launched = list(insts), [], []
        self.region = "ap-south-1"
        self.log = lambda m: None
    def default_vpc_subnet(self): return "vpc-1", "subnet-1"
    def security_group(self, vpc): return "sg-1"
    def allow_only(self, sg, ip): pass
    def instances(self): return [i for i in self.insts if i["InstanceId"] not in self.terminated]
    used = 0
    def month_usage(self, ledger): return self.used
    def launch(self, pw, sg, subnet, hours=12, cap_bytes=0, size="t3.micro"):
        self.launched.append("i-new")
        self.launch_hours, self.launch_cap, self.launch_size = hours, cap_bytes, size
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
    a.connected_ip, a.health_failures = None, 0
    a.log = lambda m: None
    a.save_hours = lambda: None
    a.run = lambda job, steps, headline: job()  # synchronous, exceptions propagate
    app.load_settings = lambda path=None: {"mfa": False, "region": "ap-south-1", "ssm_role": "", "max_hours": 5,
                                           "allow_over": False, "size": "t3.micro"}
    mem = {"instances": {}, "warned": {}}
    app.load_ledger = lambda path=None: json.loads(json.dumps(mem))
    app.save_ledger = lambda ledger, path=None: mem.update(ledger)
    app.record_instance = lambda iid, region, path=None, now=None: mem["instances"].update({iid: {"region": region}})
    a.ledger = mem
    a.aws = lambda: aws
    for name, fn in {"find_singbox": lambda: "sing-box.exe", "ensure_config": lambda: False,
                     "load_config": lambda: {"outbounds": [{"tag": "ss-out", "password": "pw"}]},
                     "warp_connected": lambda: False, "stop_singbox": lambda: None, "my_ips": lambda **k: {"1.2.3.4"},
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
app.wait_port = lambda *a, **k: None
aws = FakeAws([{"InstanceId": "i-stopped", "State": {"Name": "stopped"}, "LaunchTime": now}])
a = fake_app(aws)
app.singbox_running = lambda: True  # after a successful Start the tunnel is up
a.start()
app.singbox_running = lambda: False
assert aws.terminated == ["i-stopped"] and aws.launched == ["i-new"]
assert aws.launch_hours == 5, "the auto-delete hours chosen on the main window reach the server"
assert a.connected_ip == "5.6.7.8"
msgs = kinds(a)
assert any(k == "popup" and "Successfully connected" in m and "Reconnect" in m for k, m in msgs)
assert ("start_label", "Reconnect") in msgs, "while a server runs, Start becomes Reconnect"
assert any(k == "status" and m[1] == "ok" and "Connected via" in m[0] for k, m in msgs)
reported = [m for k, m in msgs if k == "step"]
assert reported == [s[0] for s in app.START_STEPS], reported

# 4. Stop verifies nothing is left; a leftover raises a warning
a.stop()
msgs = kinds(a)
assert aws.instances() == [] and not any(k == "warn" for k, m in msgs) and a.connected_ip is None
assert ("start_label", "Start") in msgs
aws.leftovers = lambda: ["vol-123"]
a.stop()
assert any(k == "warn" and "vol-123" in m for k, m in kinds(a))

# 5. A server already running when the app opens triggers a warning
aws = FakeAws([{"InstanceId": "i-old", "State": {"Name": "running"}, "LaunchTime": now}])
a = fake_app(aws)
a.first_check = True
a.report(aws)
assert a.server_up and any(k == "warn" and "already running" in m for k, m in kinds(a))

# 5b. Reopened while still connected: the app picks the connection up (no restart, no new server)
aws = FakeAws([{"InstanceId": "i-old", "State": {"Name": "running"}, "LaunchTime": now,
                "PublicIpAddress": "5.6.7.8"}])
a = fake_app(aws)
app.singbox_running, app.egress_ip = (lambda: True), (lambda: "5.6.7.8")
a.report(aws)
msgs = kinds(a)
assert a.connected_ip == "5.6.7.8" and any(k == "status" and m[1] == "ok" for k, m in msgs)
assert aws.launched == [] and aws.terminated == []

# 5c. Reopened after the server auto-deleted: the dead tunnel is stopped so the internet works again
stopped = []
aws = FakeAws([])
a = fake_app(aws)
app.singbox_running, app.stop_singbox = (lambda: True), (lambda: stopped.append(1))
a.report(aws)
assert stopped and a.connected_ip is None
assert any(k == "status" and "Not connected" in m[0] for k, m in kinds(a))
app.singbox_running, app.stop_singbox = (lambda: False), (lambda: None)

# 6. MFA sign-in: asks once per hour, cancel means no AWS access, nothing without a saved key
calls = []
real_load_key, real_assume, real_aws_cls = app.load_key, app.assume, app.Aws
app.Aws = lambda log, settings, session: ("client-for", session)
app.assume = lambda record, code, region: (calls.append(code) or "SESSION", datetime.now(timezone.utc) + timedelta(hours=1))
real_settings = app.load_settings
app.load_settings = lambda: {"mfa": True, "region": "ap-south-1", "ssm_role": ""}
b = app.App.__new__(app.App)
b.q, b.log, b.session, b.session_expiry = queue.Queue(), (lambda m: None), None, None
app.load_key = lambda: None
try:
    b.aws(); raise AssertionError("no key saved -> must not proceed")
except app.NoKeyError:
    pass
app.load_key = lambda: {"key_id": "k"}  # saved without MFA, but MFA now required -> must re-save
try:
    b.aws(); raise AssertionError("MFA on with a no-MFA key must not proceed")
except app.NoKeyError:
    pass
app.load_key = lambda: {"key_id": "k", "role_arn": "arn:aws:iam::1:role/r", "mfa_serial": "m"}
b.ask_mfa = lambda: None  # user pressed Cancel
try:
    b.aws(); raise AssertionError("cancelled sign-in must not proceed")
except app.SignInCancelled:
    pass
b.ask_mfa = lambda: "123456"
assert b.aws() == ("client-for", "SESSION") and b.aws() == ("client-for", "SESSION")
assert calls == ["123456"], "one MFA prompt per session, not per action"
b.session_expiry = datetime.now(timezone.utc) + timedelta(minutes=2)  # about to expire -> sign in again
b.aws()
assert calls == ["123456", "123456"]
# MFA turned off: the key is used directly, never a code prompt, and the session does not expire
real_key_session = app.key_session
app.key_session = lambda record: "KEY-SESSION"
app.load_settings = lambda: {"mfa": False, "region": "ap-south-1", "ssm_role": ""}
b.session, b.session_expiry, calls[:] = None, None, []
b.ask_mfa = lambda: (_ for _ in ()).throw(AssertionError("must not ask for MFA when it is off"))
assert b.aws() == ("client-for", "KEY-SESSION") and b.session_valid() and calls == []
app.load_key, app.assume, app.Aws = real_load_key, real_assume, real_aws_cls
app.load_settings, app.key_session = real_settings, real_key_session
try:
    app.assume({"key_id": "k"}, "12ab56", "ap-south-1"); raise AssertionError("bad MFA code format accepted")
except ValueError:
    pass

# server setup: static (musl) build, binary checked, success only once the port really listens
ud = app.user_data("x")
assert "linux-musl" in ud and "linux-gnu" not in ud, "the -gnu build crash-loops on Amazon Linux 2023 (glibc too old)"
assert ud.index("ssserver --version") < ud.index("systemctl enable")
assert ud.index("ss -ltn") < ud.index("echo SS-SETUP-DONE") and "SS-SETUP-FAILED" in ud

# ---- monthly data cap ----
# server script: the cap service is installed with the exact byte limit, before anything else can fail
ud_cap = app.user_data("x", 12, 12_345_678_901)
assert "data-cap.sh" in ud_cap and "-ge 12345678901 ]" in ud_cap and "systemctl enable --now data-cap" in ud_cap
assert ud_cap.index("enable --now data-cap") < ud_cap.index("curl "), "cap must be active before setup can fail"
assert "data-cap" not in app.user_data("x", 12, 0), "no cap when going over is allowed"
r = subprocess.run([bash, "-n"], input=ud_cap.encode(), capture_output=True)
assert r.returncode == 0, r.stderr
assert "cloudwatch:GetMetricStatistics" in json.dumps(app.iam_policy("ap-south-1"))

# month_usage: sums this month's hourly NetworkOut of the app's servers in this region, deleted ones included
class FakeCW:
    def __init__(self): self.calls = []
    def get_metric_statistics(self, **k):
        self.calls.append((k["Dimensions"][0]["Value"], k["StartTime"]))
        return {"Datapoints": [{"Sum": 2e9}, {"Sum": 1e9}]}
u = app.Aws.__new__(app.Aws)
u.region, u.cw = "ap-south-1", FakeCW()
nov = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
ledger = {"instances": {
    "i-this-month": {"region": "ap-south-1", "launched": "2026-11-05T10:00:00+00:00"},
    "i-crossed-midnight": {"region": "ap-south-1", "launched": "2026-10-31T20:00:00+00:00"},
    "i-last-month": {"region": "ap-south-1", "launched": "2026-10-10T10:00:00+00:00"},
    "i-other-region": {"region": "eu-west-1", "launched": "2026-11-06T10:00:00+00:00"}}, "warned": {}}
assert u.month_usage(ledger, nov) == 6e9
assert sorted(c[0] for c in u.cw.calls) == ["i-crossed-midnight", "i-this-month"]
assert all(c[1] == datetime(2026, 11, 1, tzinfo=timezone.utc) for c in u.cw.calls), "count from the 1st (UTC)"
class DeniedCW:
    def get_metric_statistics(self, **k): raise RuntimeError("AccessDenied")
u.cw = DeniedCW()
try:
    u.month_usage({"instances": {}, "warned": {}}, nov); raise AssertionError("empty ledger must still test access")
except RuntimeError:
    pass

# ledger: records servers, forgets ones older than CloudWatch keeps
d = tempfile.mkdtemp()
lf = os.path.join(d, "usage.json")
open(lf, "w").write(json.dumps({"instances": {"i-old": {"region": "r", "launched": "2026-01-01T00:00:00+00:00"}},
                                "warned": {"2026-11": [0.8]}}))
app.load_ledger, app.save_ledger = REAL["load_ledger"], REAL["save_ledger"]
REAL["record_instance"]("i-new", "ap-south-1", lf, nov)
saved = REAL["load_ledger"](lf)
assert list(saved["instances"]) == ["i-new"] and saved["warned"] == {"2026-11": [0.8]}
assert REAL["load_ledger"](os.path.join(d, "missing.json")) == {"instances": {}, "warned": {}}
shutil.rmtree(d)

# thresholds and refresh rate
GB = 10**9
assert app.due_warnings(79 * GB, []) == [] and app.due_warnings(81 * GB, []) == [0.8]
assert app.due_warnings(96 * GB, [0.8]) == [0.95] and app.due_warnings(96 * GB, [0.8, 0.95]) == []
assert app.due_warnings(None, []) == []
assert app.poll_seconds(10 * GB, False) == 900 and app.poll_seconds(92 * GB, False) == 300
assert app.poll_seconds(92 * GB, True) == 900, "no need to hurry when there's no cap"
assert "12.3 GB of the free 100 GB" in app.data_text(12.3 * GB, False) and "87.7 GB left" in app.data_text(12.3 * GB, False)
assert "IAM policy" in app.data_text(None, False)

# Start passes the remaining allowance to the new server; refuses when it can't measure or nothing is left
aws = FakeAws()
a = fake_app(aws)
app.singbox_running = lambda: True
aws.used = 40 * GB
a.start()
assert aws.launch_cap == app.CAP_BYTES - 40 * GB and "i-new" in a.ledger["instances"]
assert aws.launch_size == "t3.micro", "the size chosen in Settings reaches the launch"
app.singbox_running = lambda: False
for used, words in ((None, "can't read"), (99.9 * GB, "used up")):
    aws = FakeAws(); a = fake_app(aws); aws.used = used
    try:
        a.start(); raise AssertionError("must refuse to start")
    except RuntimeError as e:
        assert words in str(e) and aws.launched == [], (words, str(e))
aws = FakeAws(); a = fake_app(aws); aws.used = 99.9 * GB
app.load_settings = lambda path=None: {"mfa": False, "region": "ap-south-1", "ssm_role": "", "max_hours": 5,
                                       "allow_over": True, "size": "t3.micro"}
app.singbox_running = lambda: True
a.start()
assert aws.launch_cap == 0, "going over allowed: no cap on the server"
app.singbox_running = lambda: False

# a running server started by an older version (not in the ledger) is added, so its data counts
aws = FakeAws([{"InstanceId": "i-legacy", "State": {"Name": "running"}, "LaunchTime": now}])
a = fake_app(aws)
a.report(aws)
assert "i-legacy" in a.ledger["instances"]

# warnings pop up once a month; a server that stopped itself at the limit is explained
aws = FakeAws(); a = fake_app(aws); aws.used = 96 * GB
a.report(aws); first = [m for k, m in kinds(a) if k == "warn"]
a.report(aws); second = [m for k, m in kinds(a) if k == "warn"]
assert len(first) == 2 and "80 %" in first[0] and "95 %" in first[1] and second == [], (first, second)
aws.used = app.CAP_BYTES
a.report(aws)
msgs = kinds(a)
assert any(k == "warn" and "stopped itself" in m for k, m in msgs)
assert any(k == "status" and "free 100 GB of data is used up" in m[0] for k, m in msgs)

# versions and the update notice
assert app.version_tuple("v1.2.10") == (1, 2, 10) and app.version_tuple("1.0.0") == (1, 0, 0)
assert app.version_tuple("v1.10.0") > app.version_tuple("1.9.9"), "compare numerically, not as text"
changelog = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "CHANGELOG.md"), encoding="utf-8").read()
assert f"## {app.__version__}" in changelog, "every version needs a CHANGELOG entry (it becomes the release notes)"
class Rel(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): pass
real_urlopen = app.urllib.request.urlopen
app.urllib.request.urlopen = lambda *a, **k: Rel(b'{"tag_name": "v99.0.0"}')
assert app.newer_release() == "v99.0.0"
app.urllib.request.urlopen = lambda *a, **k: Rel(json.dumps({"tag_name": "v" + app.__version__}).encode())
assert app.newer_release() is None
app.urllib.request.urlopen = lambda *a, **k: (_ for _ in ()).throw(OSError("offline"))
assert app.newer_release() is None, "no network must never break the app"
app.urllib.request.urlopen = real_urlopen

# safety net is scheduled before anything that could fail
ud = app.user_data("x")
assert ud.index("shutdown -h +") < ud.index("curl ")
print("all checks passed" + ("" if exe else " (sing-box check skipped)"))
