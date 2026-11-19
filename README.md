# Proxy on demand

A one-click Windows app that runs your own private Shadowsocks proxy on **your own AWS account**. The server exists only while you use it.

- **Start**: builds a fresh server, connects your laptop to it, and shows **"Successfully connected"** when all your traffic goes through it. Takes about 2–3 minutes.
- **Stop**: disconnects, then deletes the server, its public IP and its disk, so nothing keeps billing.

No SSH, no Linux commands, no passwords to type. The app creates and remembers the proxy password for you.

---

## Quick Start

Allow about 20 minutes the first time. After that it's one click.

### Step 1: Create an AWS account

Follow AWS's official guide: [Create an AWS account](https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-creating.html).

**Cost:** see the official [AWS Free Tier](https://aws.amazon.com/free/) and [free plan details](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/free-tier-plans.html).
- At the time of writing, new accounts get **USD 100 in credits**, plus up to **USD 100 more** for completing a few activities in the console (do them; they're quick).
- The free plan lasts 6 months or until the credits run out, whichever comes first, and the credits cover this app's usage.
- Your balance is shown in the Billing and Cost Management console. Check the official pages for the current terms; they change from time to time.

### Step 2: Set a budget alert (2 minutes, strongly recommended)

Follow [Creating a budget](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-create.html) and choose the **Monthly cost budget** template. Set a small amount such as USD 5 and your email address. AWS will email you if spending heads past it.

### Step 3: Install Python on your laptop

Get Python 3.11 or newer from [python.org](https://www.python.org/downloads/windows/). During setup, tick **"Add python.exe to PATH"**.

### Step 4: Download this app

Click the green **Code** button on this page → **Download ZIP**, then unzip it anywhere. (Or `git clone` it.)

### Step 5: Open the app and copy its IAM policy

1. Double-click **`Start Proxy App.bat`** and accept the Windows admin prompt. The app needs admin rights to create its network adapter.
2. The **AWS settings** window opens.
   - **Region:** choose the AWS region nearest to you, for example `ap-south-1` (Mumbai), `eu-west-2` (London) or `us-east-1` (N. Virginia). See [all region codes](https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html).
   - Leave **Session Manager role** empty unless you know you want it (see [Advanced](#advanced)).
3. Click **Copy IAM policy**. The policy is now on your clipboard. Keep the window open.

### Step 6: Create an IAM user just for this app

Never use your root (email) login or an administrator key for this app.

1. In the AWS console, create the policy: follow [Creating policies with the JSON editor](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_create-console.html#access_policies_create-json-editor), paste the copied policy, and name it `proxy-on-demand`.
2. Create a user: follow [Create an IAM user](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html). Name it `proxy-on-demand`, **do not** give it console access, and on the permissions step choose **Attach policies directly** → `proxy-on-demand`.
3. Create an access key for that user: follow [Managing access keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-keys-admin-managed.html). When asked for the use case, choose **Local code**.

### Step 7: Paste the key into the app

Back in the app's **AWS settings** window, paste the **Access key ID** and **Secret access key**, then click **Save and test**.

The app checks the key with AWS straight away:
- It refuses a key that doesn't work.
- It warns you if the key is a root key, has admin rights, or is missing the policy.

The key is stored in the standard AWS credentials file (`%USERPROFILE%\.aws\credentials`, profile `proxy-on-demand`), the same place the official AWS tools use. It never goes into this folder, and the app never shows the secret again.

### Step 8: Press Start

On the first Start the app also downloads sing-box, the VPN engine. It's the official release, and the app checks it against a pinned checksum. When you see **"Successfully connected"**, all your traffic goes through your server.

**Press Stop when you're done.** The app confirms that nothing is left billing.

---

## What it does

**Start:**
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
| Your AWS key leaks | The app's IAM policy allows only small tagged `t3.micro` servers from Amazon images in your one region. It can only touch what the app created, and has no IAM rights. |
| Anything else, such as data-transfer charges | Your budget alert from Step 2. |

## Cost (approximate)

While a server exists: about **USD 0.02 per hour** (`t3.micro` + public IPv4 address + 8 GB disk, Mumbai prices). This is covered by free-plan credits.

**Data you download through the proxy** counts as AWS outbound data transfer: the first 100 GB per month are free, after that roughly USD 0.09–0.11 per GB depending on region.

After Stop: nothing. The app's security group is free.

## Troubleshooting

| Symptom | Fix |
|---|---|
| AWS settings opens on every launch | No key is saved yet. Do Step 7. |
| "This key cannot use EC2" | The policy isn't attached to the key's user (Step 6), or the region in the app doesn't match the region you copied the policy for. |
| "No default VPC" | Follow [Default VPCs](https://docs.aws.amazon.com/vpc/latest/userguide/work-with-default-vpc.html) to create one. |
| "did not open in 7 min" | Server setup failed. In the EC2 console: instance → Actions → Monitor and troubleshoot → Get system log, and look for `SS-SETUP-DONE`. |
| Connected, then it stops working | Your public IP changed. Press Start again. |
| "Traffic left via …" | Another VPN is active. Turn it off and press Start. |
| Works on one network but not another | Some networks block this kind of traffic even on port 443. |

## Files on your laptop

| What | Where |
|---|---|
| App log | `%LOCALAPPDATA%\proxy-on-demand\app.log` |
| App settings (region, role) | `%LOCALAPPDATA%\proxy-on-demand\settings.json` |
| sing-box (downloaded by the app) | `%LOCALAPPDATA%\proxy-on-demand\sing-box\` |
| Proxy config, which holds your proxy password | `%LOCALAPPDATA%\sing-box\config.json` |
| AWS key | `%USERPROFILE%\.aws\credentials`, profile `proxy-on-demand` |

None of these are inside the app folder, so sharing or committing the app folder never shares your secrets.

## Advanced

- **Session Manager (shell access to the server):** create an EC2 role with the `AmazonSSMManagedInstanceCore` policy ([guide](https://docs.aws.amazon.com/systems-manager/latest/userguide/setup-instance-permissions.html)) and enter its name in AWS settings. Then click **Copy IAM policy** again and update your `proxy-on-demand` policy: the copied policy now also allows passing that one role.
- **Keep a failed server for debugging:** set `KEEP_FAILED_SERVER = True` in `proxy_app.py`. It then bills until you press Stop.
- **Auto-delete time:** `MAX_HOURS` in `proxy_app.py` (default 12).

## Development

```
pip install -r requirements.txt
python test_proxy_app.py
```

The tests run offline and make no AWS calls. Set `SINGBOX_EXE` to a `sing-box.exe` to also validate the generated config. CI runs the tests on every push. `iam-policy.json` is the Mumbai policy, generated from `iam_policy()` in the app; a test fails if the two drift apart.
