# Changelog

All notable changes to this project. Versions follow [Semantic Versioning](https://semver.org/). Each version's section here becomes its GitHub Release notes.

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
