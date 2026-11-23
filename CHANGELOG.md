# Changelog

All notable changes to this project. Versions follow [Semantic Versioning](https://semver.org/). Each version's section here becomes its GitHub Release notes.

## 2.0.0

- **A new window.** Rebuilt as a modern page shown by Windows' own Edge engine (WebView2), still started with `Start Proxy App.bat` and Python, so it works with Smart App Control on.
  - A slim sidebar: Home, Cost and data, Sharing, Activity; the theme switch and Settings sit at the bottom.
  - **No pop-up windows.** Everything the app has to say appears inside the window: notices, warnings, the MFA code, the sharing agreement, and "Stop the server before closing?".
  - **A live route:** This laptop (or This PC) → your server → Internet. Each step shows what the app last checked (tunnel, server region, size, IP, response time, whether traffic really leaves through the server) and turns red with the reason when it fails.
  - **Cost and data as headline numbers:** this session, this month, data used out of the free 100 GB with its reset date, and AWS credits left.
  - **A bold "Update your IAM policy" banner** when the app finds a permission missing, with a Copy button and the steps.
- **Real prices.** Costs use AWS's own list prices for your region and size, shipped with the app (`prices.json`), with the server, its public IP address and its disk shown separately. Example: in Mumbai a t3.micro server is $0.0112 an hour, its public IP $0.0050 and its disk $0.0010, so $0.0172 an hour in total.
- **This month's cost without paying to check it.** The app works out the month's cost on your PC from each server's running time, so checking is free. Next to it, it shows AWS's own figure from a free AWS Budgets budget limited to the app's servers. Cost Explorer, which charges $0.01 a check, is no longer used.
- **Credits left** on your AWS account (AWS free plan accounts).
- **When the free 100 GB resets**, for example "Resets 1 Dec (in 8 days)".
- **The supported way to run the app is from source with Python 3.11:** run `Start Proxy App.bat` as administrator. The unsigned `.exe` is blocked by Smart App Control, so it isn't recommended until it's code-signed.
- **Action needed:** copy the IAM policy again when the app asks. It adds read-only access to one AWS Budgets budget (`proxy-on-demand`) and to your credit balance. For AWS's own figure, also activate the `app` cost allocation tag once (see "Seeing the real bill and your credits" in the README). Without these steps everything else works.

## 1.4.0

- **New look.** A graphite-and-green theme in dark and light. Each screen's main button (Start, Connect with a link) stands out in solid white (dark) or black (light).
- **Connection map.** The status card shows This laptop → server → Internet, joined by lines: solid green when connected, dotted amber while connecting, red on an error, grey when idle.
- **Share my server is a slider** instead of a checkbox. Click it or its label, or use Tab and Space.

## 1.3.0

- **Sharing (simple version).** Let up to 5 devices at once, you included, use your server with one link.
  - Turn it on with the **Share my server** switch on the main window, after a one-time agreement: trusted people only, you pay, you're responsible under AWS's Acceptable Use Policy, you'll cut off misuse.
  - The main window always shows the sharing state; while it's on, it shows the share link and **the devices connected right now** by IP address, with yours marked "(you)".
  - You're warned if more than 5 connect. The limit is shown and warned about, not yet enforced.
  - Turning sharing off, or Stop, cuts everyone off.
- **Join a friend.** A separate screen (Connect with a link, Disconnect, Refresh) for using someone else's server with their link. No AWS account needed. Disconnect never touches AWS, and the app warns you first that the owner can see your IP address and the sites you visit.
- **Two screens.** Each launch asks "Run my own server" or "Join a friend's server", unless something is already running, and shows only that screen's buttons. A link at the top right switches between them. First-time owners land straight on Settings → AWS access.
- **In-app help:** "How sharing works" explains links, removing people, costs and responsibilities.
- **One-click updates.** When a new version is released, the app offers to update. It downloads the release, checks its checksum, replaces itself in place with no duplicates left behind, and restarts while your connection stays up. Works for the `.exe` and for run-from-source copies; git clones are told to `git pull`.
- **Theme switch** (☾/☀) in the window's corner, starting from the Windows setting. The Appearance tab is gone.
- **Copy buttons** now look like buttons, and after copying, the pop-up lists the exact steps and names (`proxy-on-demand-ec2`, `proxy-on-demand`, `proxy-on-demand-role`), with a link to the matching README section.
- Servers started by 1.3.0 run a small status page on port 8443, reachable only from your network with a secret token, so the app can list connected devices.

## 1.2.0

- **Simpler by default.** MFA is now an opt-in extra (Settings → Security). The Quick Start leads with the quickest path: run from source, one IAM user, one policy.
- **Settings window with tabs.** "AWS access" holds only the key, the region and Copy IAM policy. Optional things live in "Server & data", "Security" and "Appearance". The main window shows one line about the next session, with a "Change in Settings" link.
- **Server size.** Choose Small (`t3.micro`), Medium (`t3.small`) or Large (`t3.medium`), with a live cost estimate. Costs shown everywhere now follow the size actually running.
- **Dark mode.** Theme: same as Windows, Light or Dark, including a dark title bar.
- **Action needed for existing users:** the IAM policy now allows the three sizes. Copy it again (Settings → Copy IAM policy, or Copy role permissions with MFA) and replace `proxy-on-demand-ec2`'s JSON, or larger sizes will be refused.

## 1.1.0

- **Free-data cap (on by default).** Each server stops itself, which deletes it, when this month's data reaches 99.99 GB, just under AWS's free 100 GB.
  - The server enforces it on its own every 5 seconds, even while your laptop is off.
  - The app shows "Data this month: x of the free 100 GB" and warns at 80 % and 95 %.
  - It explains when a server stopped at the limit, and blocks Start until the 1st of the next month.
  - Opt out with "Allow going over the free 100 GB" in AWS settings.
- **Adaptive refresh.** While a server runs, the window updates every 15 minutes, or every 5 minutes within 10 GB of the limit.
- **New look.** Cleaner card-based design that sizes itself from the screen's DPI, so it looks the same on 1080p, 1440p and 4K laptops. Text is sharp on high-resolution screens, and the activity log is hidden until you ask for it.
- `ProxyOnDemand.exe` now carries its product name and version in its Windows file properties.
- **Action needed for existing users:** the app's IAM policy gains one read-only permission, `cloudwatch:GetMetricStatistics`, to measure data. See "Updating your IAM policy" in the README.

## 1.0.0

First release.

- **One-click proxy on your own AWS account.**
  - Start launches a `t3.micro` server that installs Shadowsocks on first boot, connects sing-box to it, and verifies that your traffic leaves through the server.
  - Stop deletes the server, its public IP and its disk, then verifies that nothing is left billing.
- **Billing fail-safes:**
  - servers delete themselves at a time you choose (1–24 h);
  - a failed Start cleans up the server it launched;
  - warnings for servers left running;
  - a check after Stop that nothing is left;
  - only one server at a time.
- **Security:**
  - least-privilege IAM policies that can only touch resources tagged by the app;
  - optional MFA (on by default), with 1-hour credentials kept in memory only;
  - the AWS key is stored encrypted with Windows DPAPI;
  - the server accepts connections only from your network's public IPs;
  - no SSH port.
- **Usability:**
  - a progress bar with time left;
  - cost so far and maximum cost;
  - Reconnect after a network change, plus a connection health check;
  - resumes an existing connection when reopened;
  - automatic Cloudflare WARP handling;
  - a single-instance guard;
  - a notice when a new version is released.
- **Distribution:**
  - `ProxyOnDemand.exe`, built and self-checked by GitHub Actions and published with a SHA-256 checksum;
  - pinned dependencies;
  - Dependabot.
