# Proxy on demand

A one-click Windows app that runs your own private Shadowsocks proxy on **your own AWS account**. The server exists only while you use it.

- **Start**: builds a fresh server, connects your laptop to it, and shows **"Successfully connected"** when all your traffic goes through it. Takes about 2–3 minutes.
- **Stop**: disconnects, then deletes the server, its public IP and its disk, so nothing keeps billing.

No SSH, no Linux commands. The app creates and remembers the proxy password for you. To use AWS, you confirm with a 6-digit code from your phone, at most once an hour.

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

### Step 3: Install Python on your laptop

Get Python 3.11 or newer from [python.org](https://www.python.org/downloads/windows/). During setup, tick **"Add python.exe to PATH"**.

### Step 4: Download and open the app

1. Click the green **Code** button on this page → **Download ZIP**, then unzip it anywhere. (Or `git clone` it.)
2. Double-click **`Start Proxy App.bat`** and accept the Windows admin prompt. The app needs admin rights to create its network adapter.
3. The **AWS settings** window opens.
   - **Region:** choose the AWS region nearest to you, for example `ap-south-1` (Mumbai), `eu-west-2` (London) or `us-east-1` (N. Virginia). See [all region codes](https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html).
   - Leave **Session Manager role** empty unless you want it (see [Advanced](#advanced)).
4. Keep this window open. You'll come back to it.

### Step 5: Create the app's IAM user

This user can do nothing except ask for the app's role. Never use your root (email) login or an administrator key for this app.

1. In the app, click **Copy key policy**.
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

### Step 9: Add the kill switch (recommended, 5 minutes)

Make AWS lock the app out automatically if spending ever passes your limit:
1. Open the budget from Step 2 and add a **budget action**: follow [Configuring a budget action](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-action-configure.html).
2. Choose **IAM policy** as the action, the AWS-managed policy [`AWSDenyAll`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSDenyAll.html), and target the role `proxy-on-demand-role`. Set it to run **automatically**.

Also turn on [Cost Anomaly Detection](https://docs.aws.amazon.com/cost-management/latest/userguide/getting-started-ad.html). It's free and emails you about unusual spending.

### Step 10: Press Start

On the first Start the app also downloads sing-box, the VPN engine. It's the official release, and the app checks it against a pinned checksum. When you see **"Successfully connected"**, all your traffic goes through your server.

**Press Stop when you're done.** The app confirms that nothing is left billing.

---

## Security model

The goal: even if your laptop is fully compromised, stealing what's on it gets an attacker little, and the bill stays capped.

| What's on the laptop | Protection |
|---|---|
| The access key | **Useless on its own.** It can only *ask* for the app's role, and AWS grants the role only with a fresh 6-digit code from your phone. The role trusts only this one user. |
| The stored key file | Encrypted with Windows DPAPI for your Windows account (`%LOCALAPPDATA%\proxy-on-demand\aws-key.bin`). It's unreadable from a stolen disk, a backup or cloud sync. It is never in the app folder or in plain text. |
| Signed-in AWS access | Temporary 1-hour credentials, kept **only in memory**, never written to disk. Closing the app ends them. |
| What the role can do | Only start and delete small, tagged `t3.micro` servers from Amazon images, in your one region. It cannot touch anything else in your account, and has no IAM rights. |
| The bill | Servers delete themselves after 12 hours. The budget kill switch (Step 9) locks the role automatically, and Cost Anomaly Detection emails you. |

**The honest limit:** malware that is live on your laptop *while you are signed in* could use that one-hour session. Even then it can only do what the role allows, and the kill switch caps the cost. It could also see your internet traffic before it enters the tunnel, or use your proxy while it's running. That's true of any VPN on a compromised machine.

**Lost your phone?** Sign in to the AWS console with your root or admin login, remove the old MFA device from the `proxy-on-demand` user, and assign a new one.

**Key leaked?** Delete it in IAM → `proxy-on-demand` user → Security credentials, create a new one, and enter it in AWS settings.

## What Start does

1. Creates a local proxy config with a random password, the first time only.
2. Disconnects Cloudflare WARP if it's running, because two VPNs at once break the tunnel. Stop reconnects it.
3. Allows **only your current public IP** into the server's port 443 (TCP and UDP). There is no SSH port.
4. Launches an Amazon Linux 2023 `t3.micro` server. On first boot the server installs Shadowsocks-rust (checksum-verified) and runs it as a locked-down service.
5. Connects sing-box to it, then checks that your public IP really is the server's IP. If it isn't, the app disconnects, so you keep your normal internet, and deletes the new server.

Pressing **Start** while a server is already running reuses it and only updates the allowed IP. Do this after switching networks, for example from Wi-Fi to mobile data.

## Billing fail-safes

| Risk | Protection |
|---|---|
| You forget to press Stop, or your laptop dies | Every server deletes itself after 12 hours. This is scheduled first thing at boot. |
| Start fails halfway | The server it launched is deleted automatically. |
| App crashed or was closed with the server left running | A warning pops up when the app opens. |
| You lose track of time | The status line shows uptime, cost so far, and time until auto-delete. |
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
| "has no MFA device" | Do Step 6.1. |
| "cannot look up its MFA device" | The key policy isn't attached to the user (Step 5). |
| "AWS refused the sign-in" | Wait for the next code and try again. If it keeps failing, check that the role is named exactly `proxy-on-demand-role` and uses the trust policy copied from the app (Step 7). |
| "UnauthorizedOperation" on Start | The role's permissions policy is for a different region than the one set in the app. Copy role permissions again and update `proxy-on-demand-ec2`. |
| "No default VPC" | Follow [Default VPCs](https://docs.aws.amazon.com/vpc/latest/userguide/work-with-default-vpc.html) to create one. |
| "did not open in 7 min" | Server setup failed. In the EC2 console: instance → Actions → Monitor and troubleshoot → Get system log, and look for `SS-SETUP-DONE`. |
| Connected, then it stops working | Your public IP changed. Press Start again. |
| "Signed out" in the status line | The 1-hour sign-in ended. Press Refresh and enter a new code. |
| "Traffic left via …" | Another VPN is active. Turn it off and press Start. |
| Works on one network but not another | Some networks block this kind of traffic even on port 443. |

## Files on your laptop

| What | Where |
|---|---|
| App log | `%LOCALAPPDATA%\proxy-on-demand\app.log` |
| App settings (region, role) | `%LOCALAPPDATA%\proxy-on-demand\settings.json` |
| AWS key, encrypted for your Windows account | `%LOCALAPPDATA%\proxy-on-demand\aws-key.bin` |
| sing-box (downloaded by the app) | `%LOCALAPPDATA%\proxy-on-demand\sing-box\` |
| Proxy config, which holds your proxy password | `%LOCALAPPDATA%\sing-box\config.json` |

None of these are inside the app folder, so sharing or committing the app folder never shares your secrets.

## Advanced

- **Session Manager (shell access to the server):** create an EC2 role with the `AmazonSSMManagedInstanceCore` policy ([guide](https://docs.aws.amazon.com/systems-manager/latest/userguide/setup-instance-permissions.html)) and enter its name in AWS settings. Then click **Copy role permissions** again and update `proxy-on-demand-ec2`: the copied policy now also allows passing that one role.
- **Keep a failed server for debugging:** set `KEEP_FAILED_SERVER = True` in `proxy_app.py`. It then bills until you press Stop.
- **Auto-delete time:** `MAX_HOURS` in `proxy_app.py` (default 12).
- **Policies as files:** [`policies/`](policies) contains the key policy, the role permissions for `ap-south-1`, and an example trust policy (with a placeholder account). The app generates the right versions for you, so prefer its Copy buttons.

## Development

```
pip install -r requirements.txt
python test_proxy_app.py
```

The tests run offline and make no AWS calls. They cover:
- encrypted key storage, including tamper detection;
- the MFA sign-in flow;
- the policies, which a test keeps in sync with `policies/`;
- the billing fail-safes;
- the server startup script and config handling.

Set `SINGBOX_EXE` to a `sing-box.exe` to also validate the generated config. CI runs the tests on every push.
