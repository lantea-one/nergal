# Arch User Repository packages

Both x86-64 recipes install the controller, the agent, and the administration
CLI. Pacman resolves the .NET 10 and ASP.NET Core 10 runtimes, nftables, and
systemd from the Arch repositories. Choose one variant per system.

| Package | Source |
| --- | --- |
| `nergal-bin` | The latest stable CalVer Linux x64 archive on [Forgejo Releases](https://git.lantea.one/lantea-one/nergal/releases), pinned by tag and SHA-256 in the recipe. |
| `nergal-git` | The current `main` branch from Forgejo. The package version includes the source CalVer, Git commit count, and abbreviated commit ID. |

To build from this repository on Arch, install `base-devel` and run
`makepkg --syncdeps --install` as a regular user in the chosen recipe
directory. The packages install the vendor units and account definitions.
Follow the [deployment guide](../../docs/deployment.md) to configure and start
the services and explicitly enroll a firewall. If switching variants, remove the
installed package with `pacman -R` before installing the other variant.

## Maintain the AUR repositories

Copy `PKGBUILD`, `.SRCINFO`, and `LICENSE` from each recipe directory into its
corresponding AUR Git repository. Follow the [AUR submission
guidelines](https://wiki.archlinux.org/title/AUR_submission_guidelines) to
review, commit, and push the files with a maintainer account.

Attach `nergal_<CalVer>_linux-x64.tar.gz` and its matching `SHA256SUMS` from the
Linux release packaging job to the Forgejo release before publishing. The
**Verify Arch User Repository packages** workflow then selects the newest stable
CalVer, verifies the archive against the published manifest, checks that both
packages build and install, and produces a `nergal-bin-aur-recipe` artifact for
maintainer review and submission. The workflow can also run on demand.

On Arch, maintainers can prepare the same binary update locally by running
`python deploy/aur/update-bin.py` in a Nergal checkout. Pass a local
`nergal-bin` AUR checkout as the optional directory argument to update its
`PKGBUILD` and `.SRCINFO` directly. A published release without the expected
archive or a matching checksum causes the update to fail.

For `nergal-git`, update the SDK source URL and SHA-512 alongside a change to
`global.json`. Use the [Microsoft .NET release
metadata](https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json)
and regenerate `.SRCINFO` with `makepkg --printsrcinfo > .SRCINFO` when recipe
metadata changes. Each install rebuilds from Git with locked NuGet dependencies.
