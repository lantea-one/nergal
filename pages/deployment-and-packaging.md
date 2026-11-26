# Deployment & Packaging

nergal is designed for Linux hosts running `systemd` and `nftables` with strict privilege separation between `nergal-agent` and `nergal-web`.

Native nftables is the sole firewall engine. Windows-native service deployments
and other firewall adapters are outside scope. Browser clients do not run the
controller or agent services. See
[the platform decision](https://git.lantea.one/lantea-one/nergal/src/branch/main/docs/decisions/0051-nftables-only-linux-product.md).

## Release packages

The tagged release build produces Linux AMD64 packages for Debian and Ubuntu
(`.deb`), Fedora (`.rpm`), and Arch Linux (`.pkg.tar.zst`). It also produces a
tar archive and `SHA256SUMS`. Packages require .NET 10, the ASP.NET Core 10
runtime, systemd, and nftables. Install the native format with the target
distribution's package manager.

## Install and enroll

The package installs the offline administration tools, dedicated accounts and
directories, and systemd units. The controller and agent use different service
users. Prepare the HTTPS and wrapping certificates, initialize the controller
and account databases, then provision the first Administrator. Run
`systemctl start nergal-agent-enroll.service` to enroll the local agent before
enabling its control service. Register the local Unix socket in the controller
or use pinned mutual TLS for a remote host.

## Container images and Compose

Version tags build and publish Linux AMD64 images for both roles to the Forgejo
Registry. Both images carry the project's bare CalVer, such as `2026.11.21.1`.
The newest complete pair also carries `latest`. Select a CalVer or digest for
`git.lantea.one/lantea-one/nergal/controller` and `git.lantea.one/lantea-one/nergal/agent`
to pin a deployment.

Run the controller with the repository-root `docker-compose.yml`. The controller
runs as a dedicated non-root user with zero Linux capabilities, private state and
session key volumes, and read-only HTTPS credentials. On each managed Linux host,
use `deploy/container/docker-compose.agent.yml` with the separate agent image and
its protected journal and TLS credentials. Enroll the agent explicitly and
connect the controller over pinned mutual TLS. Native systemd agent installation
also works with the containerized controller.

Follow the [deployment guide](https://git.lantea.one/lantea-one/nergal/src/branch/main/docs/deployment.md)
for exact package, bootstrap, and container commands.

## Unreleased router and settings work

See [Router Migration & Local Sandbox](router-migration-and-sandbox.md) for the
current support matrix, supported apply scope and recovery limits, saved-settings/runtime distinction,
private source inspection, container isolation, verification limits, and screenshots.
This local development work is not a published release.

## Shared organization CI runners

Build verification uses shared `asgard-ci`; Pages publication uses shared
`heimdall-ci`, which has the established network path to the publication service.
Labels must end in `-ci`, and registration must be organization-owned without a
repository binding. A suffix alone does not prove shared scope. Private
infrastructure runners and generic label fallbacks are prohibited.

`vidar-ci` may run small, short tasks such as documentation validation/publication
when available in the shared organization pool. Never assign it the full .NET
build, integration suite or release packaging. The offline runner-policy check
guards reviewed labels and prevents that heavy-workflow assignment; operators
must verify registration scope separately when maintaining the pool.

Forks must select their own verified shared organization CI runners and update the
reviewed workflow policy. Changes to labels require review; arbitrary repository
variable values cannot redirect these workflows to infrastructure. The existing
Pages token and publication destination are unchanged. Previously queued runs
retain their original selections and must be cancelled if disallowed.
