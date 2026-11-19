# Proxy on demand

A one-click Windows app that runs your own private Shadowsocks proxy on **your own AWS account**. The server exists only while you use it.

- **Start**: builds a fresh server, connects your laptop to it, and shows **"Successfully connected"** when all your traffic goes through it. Takes about 2–3 minutes.
- **Stop**: disconnects, then deletes the server, its public IP and its disk, so nothing keeps billing.

No SSH, no Linux commands. The app creates and remembers the proxy password for you. By default, using AWS also needs a 6-digit code from your phone, at most once an hour. Experienced users can turn that off.

---

## Quick Start

Allow about 30 minutes the first time. After that it's one click and one phone code.

### Step 1: Create an AWS account

Follow AWS's official guide: [Create an AWS account](https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-creating.html).

**Cost:** see the official [AWS Free Tier](https://aws.amazon.com/free/) and [free plan details](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/free-tier-plans.html).
- At the time of writing, new accounts get **USD 100 in credits**, plus up to **USD 100 more** for completing a few activities in the console (do them; they're quick).
- The free plan lasts 6 months or until the credits run out, whichever comes first, and the credits cover this app's usage.
- Your balance is shown in the Billing and Cost Management console. Check the official pages for the current terms; they change from time to time.

### Step 2: Set a budget alert (2 minutes)

Follow [Creating a budget](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-create.html) and choose the **Monthly cost budget** template. Set a small amount such as USD 5 and your email address. AWS will email you if spending heads past it.

### Step 3: Get the app

**Option A: download the app (no Python needed).**
1. Open the [latest release](../../releases/latest) and download **`ProxyOnDemand.exe`** (and `ProxyOnDemand.exe.sha256` if you want to verify it).
2. Optional: check the file is genuine. In PowerShell, run `Get-FileHash .\ProxyOnDemand.exe`, and compare the result with the value in the `.sha256` file.
3. Put it anywhere, for example a `Proxy on demand` folder on your Desktop.

> **Windows may warn about the app.** The `.exe` isn't code-signed yet, so Windows doesn't know the publisher.
> - **"Windows protected your PC"** (SmartScreen): click **More info → Run anyway**.
> - **"Smart App Control blocked an app"**: Windows 11's Smart App Control doesn't allow unsigned apps at all, and it shouldn't be turned off for this. Use Option B instead.

**Option B: run from source.**
1. Install Python 3.11 or newer from [python.org](https://www.python.org/downloads/windows/). During setup, tick **"Add python.exe to PATH"**.
2. On this page click **Code → Download ZIP**, and unzip it anywhere (or `git clone` it).

### Step 4: Open the app

1. **Option A:** double-click `ProxyOnDemand.exe`. **Option B:** double-click `Start Proxy App.bat`; the first run installs the one Python dependency.
2. Accept the Windows admin prompt. The app needs admin rights to create its network adapter.
3. The **AWS settings** window opens.
   - **Require MFA (recommended)** is ticked. Keep it ticked and follow Steps 5–8, unless you are comfortable with AWS and prefer no phone codes; in that case untick it and follow [Setup without MFA](#setup-without-mfa) instead. You can change this later.
   - **Region:** choose the AWS region nearest to you, for example `ap-south-1` (Mumbai), `eu-west-2` (London) or `us-east-1` (N. Virginia). See [all region codes](https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html).
   - Leave **Session Manager role** empty unless you want it (see [Advanced](#advanced)).
4. Keep this window open. You'll come back to it.

### Step 5: Create the app's IAM user

With MFA on, this user can do nothing except ask for the app's role. Never use your root (email) login or an administrator key for this app.

1. In the app, click **Copy user policy**.
2. In the AWS console, create a policy from it: follow [Creating policies with the JSON editor](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_create-console.html#access_policies_create-json-editor), paste, and name it `proxy-on-demand-key`.
3. Create a user: follow [Create an IAM user](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html).
   - Name it `proxy-on-demand`.
   - **Do not** give it console access.
   - On the permissions step, choose **Attach policies directly** → `proxy-on-demand-key`.

### Step 6: Add your phone as MFA, then create the access key

1. Open the `proxy-on-demand` user → **Security credentials** → **Assign MFA device** → **Authenticator app**. Follow [Assign a virtual MFA device](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html) and scan the QR code with an authenticator app, such as Google Authenticator or Microsoft Authenticator.
2. On the same page, create an access key: follow [Managing access keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-keys-admin-managed.html). When asked for the use case, choose **Local code**.
3. Paste the **Access key ID** and **Secret access key** into the app's AWS settings window. Don't click Save yet.

### Step 7: Create the app's role (this holds the real permissions)

1. In the app, click **Copy role permissions**. In the AWS console, create a policy from it ([JSON editor](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_create-console.html#access_policies_create-json-editor)) named `proxy-on-demand-ec2`.
2. In the app, click **Copy role trust policy**. This policy names your `proxy-on-demand` user and requires MFA.
3. In the AWS console, create the role: follow [Create a role using a custom trust policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-custom.html).
   - Paste the trust policy.
   - Attach `proxy-on-demand-ec2`.
   - Name the role exactly `proxy-on-demand-role`.

### Step 8: Save and sign in

In the app, click **Save and sign in**, then enter the 6-digit code from your authenticator app. If the status line says **"No server (not billing)"**, everything is set up correctly.

The app checks the key with AWS before saving:
- It refuses root keys, keys that AWS doesn't accept, and users without MFA.
- It warns you about admin keys.

### Setup without MFA

This replaces Steps 5–8. It's simpler: one user, one policy, no role and no phone codes. The trade-off is in the [Security model](#security-model).

1. In AWS settings, untick **Require MFA**, choose your region, and click **Copy user policy**. With MFA off, this copies the app's least-privilege EC2 permissions.
2. In the AWS console, create a policy from it ([JSON editor](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_create-console.html#access_policies_create-json-editor)) named `proxy-on-demand-ec2`.
3. [Create an IAM user](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html):
   - Name it `proxy-on-demand`.
   - **Do not** give it console access.
   - Choose **Attach policies directly** → `proxy-on-demand-ec2`.
4. [Create an access key](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-keys-admin-managed.html) for it (use case **Local code**), paste both values into the app, and click **Save and sign in**. If the status line says **"No server (not billing)"**, the setup works.

### Step 9: Add the kill switch (recommended, 5 minutes)

Make AWS lock the app out automatically if spending ever passes your limit:
1. Open the budget from Step 2 and add a **budget action**: follow [Configuring a budget action](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-action-configure.html).
2. Choose **IAM policy** as the action, with the AWS-managed policy [`AWSDenyAll`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSDenyAll.html), and set it to run **automatically**.
   - **Target:** the role `proxy-on-demand-role` (with MFA), or the user `proxy-on-demand` (without MFA).

Also turn on [Cost Anomaly Detection](https://docs.aws.amazon.com/cost-management/latest/userguide/getting-started-ad.html). It's free and emails you about unusual spending.

### Step 10: Press Start

Choose how long the server may live (see [Auto-delete](#auto-delete-and-cost)), then press **Start**. A progress bar shows each step and the time left. A fresh server usually takes **about 1–2 minutes**.

On the first Start the app also downloads sing-box, the VPN engine. It's the official release, and the app checks it against a pinned checksum. When you see **"Successfully connected"**, all your traffic goes through your server.

**Press Stop when you're done.** The app confirms that nothing is left billing.

---

## Using the app

### The main window

| Part | What it tells you |
|---|---|
| **Coloured dot and headline** | Grey: not connected, nothing billing. Orange: working. Green: connected. Amber: needs your attention (for example, a server is running but this laptop isn't connected). Red: something went wrong. |
| **Detail line** | While a server runs: how long it has run, its cost so far, the most it can cost, and when it deletes itself. |
| **Progress bar** | Shown while Start, Stop or Refresh runs. It names the current step ("Server is installing Shadowsocks", step 5 of 7) and estimates the time left from typical runs. If a step takes longer than usual, it says so instead of freezing or jumping to 100%. |
| **Start / Reconnect** | Start creates a server and connects you. While a server exists the button reads **Reconnect** (see below). |
| **Stop** | Disconnects you first, so your normal internet returns, then deletes the server and checks that nothing is left billing. |
| **Refresh** | Re-checks AWS and the connection. |
| **AWS settings** | MFA, region and access key (Quick Start Steps 4–8). |
| **Logs** | Opens the folder that holds `app.log`. |
| **Activity** | Everything the app does, step by step. The same text is saved in `app.log`. |

### Switching networks: Reconnect

Your server only accepts connections from **your network's public IPs**, so moving to a different network (from Wi-Fi to mobile data, from home to campus, or when your provider changes your IP) cuts the tunnel.

- **The app notices.** While you're connected it checks every minute that traffic still flows through your server. After two failed checks it shows **"Connection lost"**, in red, and tells you to press Reconnect.
- **Press Reconnect.** It doesn't create a new server. It:
  1. stops the tunnel;
  2. detects your new network's public IPs;
  3. replaces the server's allowed IPs with them, removing the old ones;
  4. reconnects and confirms traffic leaves through the server.

  This usually takes **under 30 seconds**, and the auto-delete countdown carries on unchanged.
- Your old network can no longer reach the server, because each Reconnect replaces the allowed IPs rather than adding to them.

### Auto-delete and cost

Below the buttons, choose **"Delete the server automatically after N hours"** (1 to 24, default 12).
- It's saved and **applies to the next server you start**. A running server keeps the time it was started with; the detail line always shows the real countdown.
- The server enforces it itself, so it is deleted even if your laptop is off, asleep or the app has crashed.

The line under it shows the cost of your choice, for example *"about $0.018 per hour, so at most about $0.22 if it runs the full 12 h"*. While a server runs, the detail line shows cost so far and the maximum. These are estimates from Mumbai prices; downloads beyond 100 GB a month cost extra. See [Cost](#cost-approximate).

### Closing and reopening the app

The app doesn't run in the background. Closing the window ends the app, but **your server and your tunnel keep their own state**, and the app reads that state from AWS and from your laptop when you open it again. Nothing is resumed blindly and nothing is deleted without you pressing Stop.

| You close the window... | What keeps running | What you see when you reopen |
|---|---|---|
| ...while connected, choosing "No, stay connected" | Server and tunnel. Your traffic keeps going through the server. | **Connected** (green). The app picks up the existing connection; nothing restarts. |
| ...while connected, choosing "Yes, stop everything" | Nothing. The app runs Stop first, then closes. | **Not connected** (grey). |
| ...during Start, before the server is launched | Nothing that costs money (at most the app's free firewall group). | **Not connected**. Press Start. |
| ...during Start, after the server is launched | The server, which finishes setting itself up. The tunnel is not connected. | A warning that a server is already running and billing, with its uptime and cost. Press **Reconnect** to finish connecting to it (no second server is made), or **Stop**. |
| ...during Stop | Possibly the server, if deletion hadn't been requested yet. The tunnel is already stopped. | Either **Not connected**, or the server still listed: press Stop again. |
| ...and the server auto-deletes before you reopen | A leftover tunnel pointing at a server that no longer exists, which blocks your internet. | The app detects this and **stops the leftover tunnel automatically**, so your internet works again. |
| ...and you restart Windows | The server only. The tunnel doesn't survive a restart. | Server running, laptop not connected: press **Reconnect** or **Stop**. |

In every case the server still deletes itself at the auto-delete time.

**The app only ever touches what it created.**
- It finds servers by the tag `app=ss-proxy-app`, which it puts on everything it launches, and it only lists, reconnects to or deletes those.
- Its IAM policy (or role) only allows terminating instances with that tag, and only changing firewall rules on its own tagged group.
- So even if you run other EC2 instances in the same account and region, the app cannot see them as its own, cannot stop them and cannot delete them. AWS itself would refuse.

Only one copy of the app can be open at a time; opening a second one just tells you the first is already open.

---

## Security model

The goal: even if your laptop is fully compromised, stealing what's on it gets an attacker little, and the bill stays capped.

| What's on the laptop | With MFA (default) | Without MFA |
|---|---|---|
| The access key | **Useless on its own.** It can only *ask* for the app's role, and AWS grants the role only with a fresh 6-digit code from your phone. The role trusts only this one user. | Works on its own, but only for what the app needs (next rows). |
| The stored key file | Encrypted with Windows DPAPI for your Windows account (`%USERPROFILE%\.proxy-on-demand\aws-key.bin`). Unreadable from a stolen disk, a backup or cloud sync. Never in the app folder or in plain text. | Same. |
| AWS access while the app runs | Temporary 1-hour credentials, kept **only in memory**. Closing the app ends them. | The key itself, in memory. |
| What a stolen credential can do | Only start and delete small, tagged `t3.micro` servers from Amazon images, in your one region. Nothing else in your account; no IAM rights. | Same limits. |
| The bill | Servers delete themselves at the time you choose (1–24 h). The budget kill switch (Step 9) locks access automatically, and Cost Anomaly Detection emails you. | Same. |

**The difference in one line:** without MFA, anyone who gets the key, for example malware on your laptop, can use it until you delete it. With MFA, they would also need your phone, or would have to strike during a one-hour session you opened.

**Limits in both modes:** malware live on your laptop could see your internet traffic before it enters the tunnel, or use your proxy while it's running. That's true of any VPN on a compromised machine.

**Lost your phone?** Sign in to the AWS console with your root or admin login, remove the old MFA device from the `proxy-on-demand` user, and assign a new one.

**Key leaked?** Delete it in IAM → `proxy-on-demand` user → Security credentials, create a new one, and enter it in AWS settings.

## What Start does

1. Creates a local proxy config with a random password, the first time only.
2. Disconnects Cloudflare WARP if it's running, because two VPNs at once break the tunnel. Stop reconnects it.
3. Allows **only your network's public IPs** into the server's port 443 (TCP and UDP). There is no SSH port. Campus and office networks often use several public IPs; the app detects all of them and keeps checking while the server starts.
4. Launches an Amazon Linux 2023 `t3.micro` server. On first boot the server installs Shadowsocks-rust (checksum-verified) and runs it as a locked-down service.
5. Connects sing-box to it, then checks that your public IP really is the server's IP. If it isn't, the app disconnects, so you keep your normal internet, and deletes the new server.

While a server already exists, the button reads **Reconnect** and skips step 4. See [Switching networks](#switching-networks-reconnect).

## Billing fail-safes

| Risk | Protection |
|---|---|
| You forget to press Stop, or your laptop dies | Every server deletes itself at the time you chose (1–24 h). This is scheduled first thing at boot, so it holds even if setup fails. |
| Start fails halfway | The server it launched is deleted automatically. |
| App crashed or was closed with the server left running | A warning pops up when the app opens. See [Closing and reopening](#closing-and-reopening-the-app). |
| You lose track of time | The detail line shows uptime, cost so far, the maximum cost, and time until auto-delete. |
| The server auto-deleted while the app was closed | The leftover tunnel is stopped automatically when you open the app. |
| Stop misses something | After Stop the app re-checks for anything it created, and warns if anything is left. |
| Two servers at once | Start never launches a second server. |
| Changing region strands a server | The app refuses to change region while a server is running. |
| Credentials are stolen | See [Security model](#security-model). |
| Anything else, such as data-transfer charges | The budget alert, kill switch and anomaly detection (Steps 2 and 9). |

## Cost (approximate)

While a server exists: about **USD 0.02 per hour** (`t3.micro` + public IPv4 address + 8 GB disk, Mumbai prices). This is covered by free-plan credits.

**Data you download through the proxy** counts as AWS outbound data transfer: the first 100 GB per month are free, after that roughly USD 0.09–0.11 per GB depending on region.

After Stop: nothing. The app's security group, IAM user and role are free.

## Troubleshooting

| Symptom | Fix |
|---|---|
| AWS settings opens on every launch | No key is saved yet. Do Steps 5–8. |
| "has no MFA device" | Do Step 6.1, or untick **Require MFA** and use [Setup without MFA](#setup-without-mfa). |
| "cannot look up its MFA device" | The user policy isn't attached to the user (Step 5). |
| "MFA is turned on, but the saved key was set up without it" | Open AWS settings and click Save again. |
| "This key cannot use EC2" (without MFA) | Attach `proxy-on-demand-ec2` to the user, and check that the policy is for the region set in the app. |
| "AWS refused the sign-in" | Wait for the next code and try again. If it keeps failing, check that the role is named exactly `proxy-on-demand-role` and uses the trust policy copied from the app (Step 7). |
| "UnauthorizedOperation" on Start | The role's permissions policy is for a different region than the one set in the app. Copy role permissions again and update `proxy-on-demand-ec2`. |
| "No default VPC" | Follow [Default VPCs](https://docs.aws.amazon.com/vpc/latest/userguide/work-with-default-vpc.html) to create one. |
| "did not open in 5 min" | Usually your network uses a public IP the app couldn't detect, or it blocks this traffic. Try again, or try another network such as a phone hotspot. To check the server itself, set `KEEP_FAILED_SERVER = True`, then in the EC2 console open the instance → Actions → Monitor and troubleshoot → Get system log, and look for `SS-SETUP-DONE`. |
| Can't find the log | Click **Logs** in the app. It opens `%USERPROFILE%\.proxy-on-demand`. |
| Connected, then it stops working, or "Connection lost" | Your network or public IP changed. Press **Reconnect**. |
| "Proxy on demand is already open" | Only one window is allowed. Look for it in the taskbar. |
| "Signed out" in the status line | The 1-hour sign-in ended. Press Refresh and enter a new code. |
| "Traffic left via …" | Another VPN is active. Turn it off and press Start. |
| Works on one network but not another | Some networks block this kind of traffic even on port 443. |

## Files on your laptop

Everything the app stores is in one folder, `%USERPROFILE%\.proxy-on-demand` (for example `C:\Users\you\.proxy-on-demand`). The **Logs** button in the app opens it.

| What | File |
|---|---|
| App log | `app.log` |
| App settings (MFA, region, role) | `settings.json` |
| AWS key, encrypted for your Windows account | `aws-key.bin` |
| sing-box (downloaded by the app), its config (holds your proxy password) and its log | `sing-box\` |

None of these are inside the app folder, so sharing or committing the app folder never shares your secrets.

The folder is deliberately not under `AppData`. The Microsoft Store version of Python silently redirects files written there into a hidden package folder, where you can't find them and where sing-box can't read its config.

## Advanced

- **Session Manager (shell access to the server):** create an EC2 role with the `AmazonSSMManagedInstanceCore` policy ([guide](https://docs.aws.amazon.com/systems-manager/latest/userguide/setup-instance-permissions.html)) and enter its name in AWS settings. Then click **Copy role permissions** again and update `proxy-on-demand-ec2`: the copied policy now also allows passing that one role.
- **Keep a failed server for debugging:** set `KEEP_FAILED_SERVER = True` in `proxy_app.py`. It then bills until you press Stop.
- **Auto-delete time:** set on the main window (1–24 h). The upper limit is `MAX_HOURS_LIMIT` in `proxy_app.py`.

- **Policies as files:** [`policies/`](policies) contains:
  - `key-policy.json`: the user policy with MFA;
  - `role-permissions.json`: the EC2 permissions for `ap-south-1`. With MFA it's attached to the role; without MFA, to the user;
  - an example trust policy, with a placeholder account.

  The app generates the right versions for your region and user, so prefer its Copy buttons.
- **Update notice:** when the app opens it asks GitHub (`api.github.com`) for the latest release and, if there's a newer one, shows it in the window title and the activity log. Nothing else is sent, and nothing is downloaded automatically.

## Known limitations

- **Windows only.** sing-box's network adapter, DPAPI encryption and the launcher are Windows-specific.
- **The `.exe` isn't code-signed yet.** Windows shows a SmartScreen warning, and Smart App Control blocks it (see Step 3). Run from source on those machines.
- **Needs admin rights** (for the network adapter).
- **Only one server at a time, in one region.** Changing region requires Stop first.
- **Estimates are estimates.** Progress times come from typical runs, and cost figures use Mumbai prices, not your live bill. The budget alert (Step 2) is the source of truth.
- **UDP through the tunnel** (some games and calls) is configured but hasn't been tested end to end.
- **Some networks block this traffic** even on port 443. Port 443 doesn't make it indistinguishable from normal HTTPS.
- **Respect your network's rules.** University, school and work networks often have acceptable-use policies about proxies and VPNs.

## Development

```
pip install -r requirements.txt
python test_proxy_app.py
python proxy_app.py --check
```

The tests run offline and make no AWS calls. They cover:
- encrypted key storage, including tamper detection;
- the MFA sign-in flow;
- the policies, which a test keeps in sync with `policies/`;
- the billing fail-safes, Reconnect and resume;
- the progress estimates;
- the server startup script and config handling;
- versioning.

Set `SINGBOX_EXE` to a `sing-box.exe` to also validate the generated config. `--check` verifies a build (bundled libraries, Tk, DPAPI) without touching AWS.

**CI** runs on every push. It runs the tests, then builds `ProxyOnDemand.exe` and runs its `--check`.

### Making a release

1. Update `__version__` in `proxy_app.py`, and add a `## x.y.z` section to [CHANGELOG.md](CHANGELOG.md). A test enforces the changelog entry.
2. Commit, then tag and push: `git tag v1.0.0 && git push origin v1.0.0`.
3. The [release workflow](.github/workflows/release.yml):
   - checks that the tag matches `__version__`;
   - runs the tests;
   - builds `ProxyOnDemand.exe` with PyInstaller and self-checks it;
   - publishes a GitHub Release with the `.exe`, its SHA-256 checksum, and the changelog section as notes.

Every Python dependency is pinned to an exact version (`requirements.txt`, plus `requirements-build.txt` for PyInstaller). Dependabot opens a pull request each month when updates exist.
