# Proxy on demand

A one-click Windows app that runs your own private Shadowsocks proxy on **your own AWS account**. The server exists only while you use it.

- **Start**: builds a fresh server, connects your laptop to it, and shows **"Successfully connected"** when all your traffic goes through it. Takes about 2–3 minutes.
- **Stop**: disconnects, then deletes the server, its public IP and its disk, so nothing keeps billing.

No SSH, no Linux commands. The app creates and remembers the proxy password for you, and keeps you inside AWS's free 100 GB of data a month unless you allow more.

---

## Quick Start

Allow about 20 minutes the first time. After that it's one click.

### Step 1: Create an AWS account

Follow AWS's official guide: [Create an AWS account](https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-creating.html).

**Cost:** see the official [AWS Free Tier](https://aws.amazon.com/free/) and [free plan details](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/free-tier-plans.html).
- At the time of writing, new accounts get **USD 100 in credits**, plus up to **USD 100 more** for completing a few activities in the console (do them; they're quick).
- The free plan lasts 6 months or until the credits run out, whichever comes first, and the credits cover this app's usage.
- Your balance is shown in the Billing and Cost Management console. Check the official pages for the current terms; they change from time to time.

### Step 2: Set a budget alert (2 minutes)

Follow [Creating a budget](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-create.html) and choose the **Monthly cost budget** template. Set a small amount such as USD 5 and your email address. AWS will email you if spending heads past it.

### Step 3: Get the app (recommended: run from source)

1. Install Python 3.11 or newer from [python.org](https://www.python.org/downloads/windows/). During setup, tick **"Add python.exe to PATH"**.
2. On this page click **Code → Download ZIP**, and unzip it anywhere, for example a `Proxy on demand` folder on your Desktop (or `git clone` it).

<details>
<summary>Alternative: the ready-made <code>ProxyOnDemand.exe</code> (no Python, but Windows may block it)</summary>

1. Open the [latest release](../../releases/latest) and download **`ProxyOnDemand.exe`**, plus `ProxyOnDemand.exe.sha256` if you want to verify it: in PowerShell run `Get-FileHash .\ProxyOnDemand.exe` and compare.
2. The `.exe` isn't code-signed, so Windows doesn't know the publisher:
   - **"Windows protected your PC"** (SmartScreen): click **More info → Run anyway**.
   - **"Smart App Control blocked an app"**: Windows 11's Smart App Control doesn't allow unsigned apps at all, and it shouldn't be turned off for this. Run from source instead.

</details>

### Step 4: Open the app

1. Double-click **`Start Proxy App.bat`** (or `ProxyOnDemand.exe`). The first run installs the one Python dependency.
2. Accept the Windows admin prompt. The app needs admin rights to create its network adapter.
3. The app asks **"How do you want to connect?"**:
   - **Run my own server:** the rest of this Quick Start. The first time, **Settings** opens on the **AWS access** tab. Choose the **Region** nearest to you, for example `ap-south-1` (Mumbai), `eu-west-2` (London) or `us-east-1` (N. Virginia). See [all region codes](https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html). Keep the window open.
   - **Join a friend's server:** paste the link they sent you and you're done. You need no AWS account and can skip the rest of this guide. See [Joining a friend's server](#joining-a-friends-server).

   The app asks this every time it opens, unless something is already running (then it shows you that instead).

### Step 5: Create the app's IAM user

Never use your root (email) login or an administrator key for this app. Give it its own user that can only do what the app needs.

1. In the app, click **Copy IAM policy**. It copies the app's least-privilege permissions for your region.
2. In the AWS console, create a policy from it: follow [Creating policies with the JSON editor](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_create-console.html#access_policies_create-json-editor), paste, and name it `proxy-on-demand-ec2`.
3. Create a user: follow [Create an IAM user](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html).
   - Name it `proxy-on-demand`.
   - **Do not** give it console access.
   - On the permissions step, choose **Attach policies directly** → `proxy-on-demand-ec2`.
4. Create an access key for it: follow [Managing access keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-keys-admin-managed.html). When asked for the use case, choose **Local code**.

### Step 6: Paste the key and save

Paste the **Access key ID** and **Secret access key** into the app and click **Save**. The app checks the key with AWS first:
- It refuses root keys and keys AWS doesn't accept.
- It warns you about admin keys.

If the status line then says **"Not connected"** with "nothing is billing", everything works.

### Step 7: Add the kill switch (recommended, 5 minutes)

Make AWS lock the app out automatically if spending ever passes your limit:
1. Open the budget from Step 2 and add a **budget action**: follow [Configuring a budget action](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-action-configure.html).
2. Choose **IAM policy** as the action, with the AWS-managed policy [`AWSDenyAll`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSDenyAll.html).
   - **Target:** the user `proxy-on-demand`, or the role `proxy-on-demand-role` if you use MFA.
   - Set it to run **automatically**.

Also turn on [Cost Anomaly Detection](https://docs.aws.amazon.com/cost-management/latest/userguide/getting-started-ad.html). It's free and emails you about unusual spending.

### Step 8: Press Start

Press **Start**. A progress bar shows each step and the time left. A fresh server usually takes **about 1–2 minutes**.

On the first Start the app also downloads sing-box, the VPN engine. It's the official release, and the app checks it against a pinned checksum. When you see **"Successfully connected"**, all your traffic goes through your server.

**Press Stop when you're done.** The app confirms that nothing is left billing.

Everything else (server size, auto-delete time, the data limit, MFA, sharing) has sensible defaults. You can change any of it under **Settings**. See [Settings](#settings).

### Extra security with MFA (optional)

With MFA, the stored key alone can do nothing: every sign-in also needs a 6-digit code from your phone, and AWS access lasts 1 hour, in memory only. It takes about 10 more minutes to set up. See the [Security model](#security-model) for the trade-off.

1. **Turn it on.** In the app open **Settings → Security** and tick **Require a code from my phone (MFA)**.
2. **Change the user's policy.** On the **AWS access** tab click **Copy IAM policy**. With MFA on, it copies a tiny policy that can only ask for the app's role. Create it as `proxy-on-demand-key`, attach it to the `proxy-on-demand` user, and detach `proxy-on-demand-ec2` from the user.
3. **Add your phone.** Open the user → **Security credentials** → **Assign MFA device** → **Authenticator app**, and follow [Assign a virtual MFA device](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html).
4. **Create the role.**
   - On the Security tab, click **Copy role permissions** and make sure `proxy-on-demand-ec2` contains it.
   - Click **Copy role trust policy**. It names your user and requires MFA.
   - [Create a role with a custom trust policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-custom.html): paste the trust policy, attach `proxy-on-demand-ec2`, and name the role exactly `proxy-on-demand-role`.
5. **Save,** and enter the code from your authenticator app.

---

## Using the app

### The main window

| Part | What it tells you |
|---|---|
| **Coloured dot and headline** | Grey: not connected, nothing billing. Orange: working. Green: connected. Amber: needs your attention (for example, a server is running but this laptop isn't connected). Red: something went wrong. |
| **Detail line** | While a server runs: how long it has run, its cost so far, the most it can cost, and when it deletes itself. Always: **how much of this month's free 100 GB of data is used**. |
| **Progress bar** | Shown while Start, Stop or Refresh runs. It names the current step ("Server is installing Shadowsocks", step 5 of 7) and estimates the time left from typical runs. If a step takes longer than usual, it says so instead of freezing or jumping to 100%. |
| **Start / Reconnect** | Start creates a server and connects you. While a server exists the button reads **Reconnect** (see below). |
| **Stop** | Disconnects you first, so your normal internet returns, then deletes the server and checks that nothing is left billing. |
| **Refresh** | Re-checks AWS and the connection. |
| **Settings** | Access key and region on the first tab; server size, auto-delete time, data limit, MFA and sharing on the others. See [Settings](#settings). |
| **Use a friend's server instead / Run my own server instead** (top right) | Switches between the two screens: your own server (Start, Stop, Settings, sharing), or a friend's server (Connect with a link, Disconnect). Each shows only its own buttons. See [Joining a friend's server](#joining-a-friends-server). |
| **☾ Dark / ☀ Light** (top right) | Switches the theme instantly. The app starts in your Windows theme. |
| **Sharing** (bottom) | The **Share my server** switch, the share link, and the devices connected right now. See [Sharing your server](#sharing-your-server). |
| **Logs** | Opens the folder that holds `app.log`. |
| **Show activity** | Unfolds a log of everything the app does, step by step. The same text is saved in `app.log`. |

The window sizes itself from your screen's scaling setting, so it looks the same on a 1080p laptop, a 1440p screen or a 4K display. Below the buttons, one line says what the next session costs at most; **Change in Settings** opens the options.

### Settings

| Tab | What's there |
|---|---|
| **AWS access** | Access key, region, and **Copy IAM policy**. All a beginner needs. |
| **Server & data** | **Size**: Small (`t3.micro`, default), Medium (`t3.small`) or Large (`t3.medium`, for more people at once), with a live estimate of the hourly and per-session cost. **Delete after** 1–24 hours. **Allow going over the free 100 GB** of data a month. |
| **Security** | Optional MFA, and an optional Session Manager role. |

Approximate prices, Mumbai, for server + public IP + disk:
- Small: about $0.017/h
- Medium: about $0.028/h
- Large: about $0.051/h

Other regions differ a little. Data beyond the free 100 GB is extra. The size and auto-delete time apply to the next server you start.

### Monthly data limit (free 100 GB)

AWS gives every account **100 GB of outbound data per month free**; beyond that, data costs about USD 0.09–0.11 per GB. Data, not server time, is what can get expensive, especially if several people use one server. So by default the app keeps you inside the free 100 GB:

- **The server enforces it itself.**
  - When you press Start, the app works out how much of this month's 100 GB is left and gives that allowance to the new server.
  - The server checks its own outgoing traffic every 5 seconds and stops itself, which deletes it, at **99.99 GB for the month**.
  - This works even if your laptop is off, asleep or the app is closed.
- **The app shows and warns.**
  - The detail line shows "Data this month: x of the free 100 GB, y left".
  - A warning pops up once at **80 GB** and once at **95 GB**.
  - If a server stopped itself at the limit, the app says so in plain words.
  - Start is then blocked until the **1st of next month (UTC)**, when the free 100 GB resets.
- **How often it updates:**
  - While a server runs, the window updates every **15 minutes**, and every **5 minutes** once less than 10 GB is left. AWS's traffic figures (CloudWatch) only update every 5 minutes, so checking more often would show nothing new.
  - The stop at the limit doesn't depend on this: the server does it within seconds.
  - **Refresh** updates immediately.
- **Going over on purpose:** tick **"Allow going over the free 100 GB of data a month"** in **Settings → Server & data**. Servers then have no data limit and keep running until Stop or auto-delete. The warnings still appear, and data beyond 100 GB is billed.

What it counts:
- Data sent by the app's servers this calendar month (UTC), including servers that already deleted themselves.
- "GB" here is 10⁹ bytes. AWS bills by 2³⁰-byte GB, so stopping at 99.99 leaves roughly 7 GB of real slack for measurement delay.
- The free 100 GB is **shared with everything else on your AWS account** that sends data to the internet, so other use isn't counted here. Your budget alert (Step 2) watches the whole account.
- Servers started by app versions before 1.1.0 aren't counted for the month they ran.

### Updating your IAM policy (when upgrading from 1.0.0)

Version 1.1.0 needs one extra, read-only permission, `cloudwatch:GetMetricStatistics`, to measure data. Until you add it, the app shows "Data this month: unknown" and refuses to start a capped server.

1. In the app open **Settings** and click **Copy IAM policy** on the AWS access tab (with MFA: **Copy role permissions** on the Security tab).
2. In the AWS console go to IAM → Policies → `proxy-on-demand-ec2` → **Edit** → JSON, replace everything with the copied text, and save.

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

### Sharing your server

You can let **up to 5 devices at once** (you included) use your server. The people you share with need no AWS account: they install this app and choose **Join a friend's server**. The app also explains all of this under **How sharing works** (bottom of the main window).

**Before you start, understand:**
- **You pay** for everything on your server: its running time and **all the data**. Everyone shares your free 100 GB a month; when it's used up, the server stops for everyone.
- **You're responsible.** Their traffic leaves through your server and your AWS account, which makes you responsible for it under the [AWS Acceptable Use Policy](https://aws.amazon.com/aup/). Share only with people you trust, never for anything illegal, abusive or unfair, and cut people off if they misuse it.
- **You can see their IP address** and which sites they visit (not the content of encrypted pages). Tell them so.

**How it works:**
1. **Turn it on:** tick **Share my server** at the bottom of the main window. The first time, you tick an agreement covering the points above.
   - While it's on, your server's port 443 accepts connections from **any network**, and the key inside the link is the only lock.
   - If a server is running, the change applies at once (the app reconnects).
2. **Share the link:** while your server runs, press **Copy share link** and send it privately, never in public chats or posts.
3. **Your friend connects:** they choose **Join a friend's server**, press **Connect with a link** and paste it. Any Shadowsocks app works too: sing-box, NekoBox, Shadowrocket.
4. **See who is connected:** the bottom of the main window shows "Sharing is on · 2 of 5 devices connected" and lists each device by IP address, with yours marked "(you)".
   - With one shared link, the server can't tell people apart by name, and two people on the same Wi-Fi count as one.
   - If more than 5 connect, the app warns you, because your link has probably been passed on. (The limit is shown and warned about, not yet enforced by the server.)

**The link's lifetime:** a link works only while your **current** server runs.
- After **Stop**, or when the server deletes itself or reaches the data limit, the next server has a new address and a new key, so old links stop working.
- **Reconnect** keeps the same server, so the link stays valid.

**Removing people:** everyone uses the same key, so you can't remove just one person. To cut everyone off:
- **Turn sharing off.** Within seconds the server accepts only your own network again.
- Or **press Stop.** The next server has a new key and address.

Then share a fresh link only with the people you still want.

**Leaving the app open?** Closing the window while sharing warns you that anyone using your link is cut off too if you choose to stop.

### Joining a friend's server

1. Open the app and choose **Join a friend's server**, or click **Use a friend's server instead** at the top right. You get a separate, simpler screen: **Connect with a link**, **Disconnect**, **Refresh**.
2. Press **Connect with a link**, paste the link (it starts with `ss://`) and press **Connect**.
3. **Disconnect** leaves. It never touches anyone's AWS account.

**Before you join:**
- Only join servers of people you trust. **The owner can see your IP address and which sites you visit** (not the content of encrypted pages).
- The owner pays for your usage and is responsible for it, so use it fairly and legally.
- The link stops working when the owner's server stops, or when they turn sharing off. Ask them for a fresh link.

### Light and dark

The app follows Windows' light or dark setting. The **☾ Dark / ☀ Light** switch in the top-right corner changes it instantly for the current session.

### Updating

When a new version is released, the app offers **"Update now?"** when it opens. If you say yes, it:
1. downloads the new version from this repository's GitHub Releases;
2. checks it against the release's published checksum;
3. replaces the old version in place (no duplicate copies are left behind);
4. restarts.

Your connection stays up during the restart, and your settings and key are kept.
- **The `.exe`:** the file is swapped in place; the old copy is deleted on the next start.
- **Run from source:** the app's files in its folder are replaced, and the dependencies are updated.
- **A git clone:** the app tells you to run `git pull` instead.

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
| The bill | Servers delete themselves at the time you choose (1–24 h). The budget kill switch (Step 7) locks access automatically, and Cost Anomaly Detection emails you. | Same. |

**The difference in one line:** without MFA, anyone who gets the key, for example malware on your laptop, can use it until you delete it. With MFA, they would also need your phone, or would have to strike during a one-hour session you opened.

**Limits in both modes:** malware live on your laptop could see your internet traffic before it enters the tunnel, or use your proxy while it's running. That's true of any VPN on a compromised machine.

**Lost your phone?** Sign in to the AWS console with your root or admin login, remove the old MFA device from the `proxy-on-demand` user, and assign a new one.

**Key leaked?** Delete it in IAM → `proxy-on-demand` user → Security credentials, create a new one, and enter it in Settings.

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
| Too much data (several users, streaming) | Servers stop themselves at 99.99 GB of data for the month, with warnings at 80 and 95 GB. See [Monthly data limit](#monthly-data-limit-free-100-gb). |
| Anything else, such as other AWS use | The budget alert, kill switch and anomaly detection (Steps 2 and 9). |

## Cost (approximate)

While a server exists: about **USD 0.02 per hour** (`t3.micro` + public IPv4 address + 8 GB disk, Mumbai prices). This is covered by free-plan credits.

**Data you download through the proxy** counts as AWS outbound data transfer: the first 100 GB per month are free, after that roughly USD 0.09–0.11 per GB depending on region.

After Stop: nothing. The app's security group, IAM user and role are free.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Settings opens on every launch | No key is saved yet. Do Steps 5–6. |
| "has no MFA device" | Add one (step 3 of [Extra security with MFA](#extra-security-with-mfa-optional)), or untick MFA in Settings → Security. |
| "cannot look up its MFA device" | The user policy isn't attached to the user (Step 5). |
| "MFA is turned on, but the saved key was set up without it" | Open Settings and click Save again. |
| "This key cannot use EC2" (without MFA) | Attach `proxy-on-demand-ec2` to the user, and check that the policy is for the region set in the app. |
| "AWS refused the sign-in" | Wait for the next code and try again. If it keeps failing, check that the role is named exactly `proxy-on-demand-role` and uses the trust policy copied from the app (Step 7). |
| "UnauthorizedOperation" on Start | The `proxy-on-demand-ec2` policy is for a different region, or from an older version (before server sizes). Click **Copy IAM policy** (or **Copy role permissions** with MFA) and replace the policy's JSON. |
| "No default VPC" | Follow [Default VPCs](https://docs.aws.amazon.com/vpc/latest/userguide/work-with-default-vpc.html) to create one. |
| "did not open in 5 min" | Usually your network uses a public IP the app couldn't detect, or it blocks this traffic. Try again, or try another network such as a phone hotspot. To check the server itself, set `KEEP_FAILED_SERVER = True`, then in the EC2 console open the instance → Actions → Monitor and troubleshoot → Get system log, and look for `SS-SETUP-DONE`. |
| Can't find the log | Click **Logs** in the app. It opens `%USERPROFILE%\.proxy-on-demand`. |
| Connected, then it stops working, or "Connection lost" | Your network or public IP changed. Press **Reconnect**. |
| "Proxy on demand is already open" | Only one window is allowed. Look for it in the taskbar. |
| "Signed out" in the status line | The 1-hour sign-in ended. Press Refresh and enter a new code. |
| "Traffic left via …" | Another VPN is active. Turn it off and press Start. |
| Works on one network but not another | Some networks block this kind of traffic even on port 443. |
| "Data this month: unknown" or "can't read this month's data usage" | Update your IAM policy (see [Updating your IAM policy](#updating-your-iam-policy-when-upgrading-from-100)). |
| "free 100 GB of data is used up" | The limit for this month is reached. Wait for the 1st (UTC), or allow going over in Settings → Server & data. |

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

- **Session Manager (shell access to the server):** create an EC2 role with the `AmazonSSMManagedInstanceCore` policy ([guide](https://docs.aws.amazon.com/systems-manager/latest/userguide/setup-instance-permissions.html)) and enter its name in Settings → Security. Then click **Copy IAM policy** (or **Copy role permissions** with MFA) again and update `proxy-on-demand-ec2`: the copied policy now also allows passing that one role.
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

## Privacy policy

The app has no servers or telemetry of its own, and the author receives nothing. It connects only to:

| Service | Why | What it sees |
|---|---|---|
| **Your own AWS account** (EC2, CloudWatch, IAM/STS) | To create, check and delete your server, and measure its data | Your requests, under your own AWS account. AWS's [privacy notice](https://aws.amazon.com/privacy/) applies. |
| **Your own server** | The proxy itself | Your internet traffic, encrypted in transit; it's then sent on to the sites you visit. |
| `checkip.amazonaws.com`, `api.ipify.org`, `ipv4.icanhazip.com` | To find your public IPs for the server's firewall, and to confirm the tunnel works | Your public IP address, as with any website. |
| `github.com`, `api.github.com` | One-time sing-box download (checksum-verified), the server's Shadowsocks download, the "new version available" check, and updates you accept (checksum-verified) | Your public IP address. Nothing is uploaded. |
| **Your server's status page** (port 8443, only from your network, secret token) | To list which devices are connected while sharing | Nothing new: your app asks your own server. |
| **A friend's server**, when you join one | The proxy itself | Your internet traffic: the owner can see your IP address and which sites you visit. |

Your AWS key, proxy password and settings stay on your laptop, in `%USERPROFILE%\.proxy-on-demand`. The key is encrypted for your Windows account.

**Changes to your system:**
- While connected, sing-box adds a network adapter (`sing-tun`) and routes, and removes them when stopped.
- If Cloudflare WARP is running, the app disconnects it during a session and reconnects it after Stop.
- Nothing else is changed.

**People you share with:** while sharing is on, your server sees the IP addresses of connected devices and which sites they visit (not the content of encrypted pages). The app shows you their IP addresses; nothing is stored or sent anywhere else.

## Uninstall

1. Press **Stop**, and wait for "Nothing is billing".
2. Delete `ProxyOnDemand.exe`, or the source folder.
3. Delete the folder `%USERPROFILE%\.proxy-on-demand`: your encrypted key, settings, logs and sing-box.
4. Optional, in the AWS console: delete the IAM user `proxy-on-demand` (with its access key), the policies `proxy-on-demand-ec2` and `proxy-on-demand-key`, the role `proxy-on-demand-role`, and the EC2 security group `ss-proxy-sg`.

## Code signing policy

Windows releases are built from this repository's source by [GitHub Actions](.github/workflows/release.yml), on GitHub-hosted runners, with every dependency pinned.

- **Committers and reviewers:** [ShRike3601](https://github.com/ShRike3601) (maintainer). Changes from anyone else, including Dependabot, are reviewed by the maintainer before they're merged.
- **Approvers:** [ShRike3601](https://github.com/ShRike3601). Each release is approved manually.
- **Privacy:** see [Privacy policy](#privacy-policy). This program won't transfer any information to other networked systems unless the user or the person running it specifically requests it, except for the services listed there.

*Releases are not code-signed yet. The project applied to [SignPath Foundation](https://signpath.org)'s free open-source signing, which requires a more established project; it will reapply as the project grows. Until then, running from source (Quick Start Step 3) avoids Windows' warnings.*

## License

[MIT](LICENSE). Use, change and share it freely; keep the copyright notice. The software comes with no warranty. You are responsible for your own AWS bill and for following the rules of the networks you use it on.
