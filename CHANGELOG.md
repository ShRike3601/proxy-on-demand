# Changelog

All notable changes to this project. Versions follow [Semantic Versioning](https://semver.org/). Each version's section here becomes its GitHub Release notes.

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
