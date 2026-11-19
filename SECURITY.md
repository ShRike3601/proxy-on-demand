# Security policy

## Reporting a vulnerability

Please **don't open a public issue** for security problems. Use GitHub's private reporting instead: this repository's **Security** tab → **Report a vulnerability**. Include what you found, how to reproduce it, and what an attacker could do with it.

You'll get a reply as soon as possible. Fixes are released as a new version, with credit to the reporter if they want it.

## What counts

Anything that could let someone:
- read or use the stored AWS key or proxy password;
- make the app act on AWS resources it didn't create;
- run up a bill beyond what the app's IAM policies allow;
- get into the proxy server.

Also anything in the release build (`ProxyOnDemand.exe`) that differs from this source.

## Supported versions

Only the latest release gets fixes. The app tells you when a newer version is available.

## Design

See [Security model](README.md#security-model) in the README for what the app protects against, and what it can't.
