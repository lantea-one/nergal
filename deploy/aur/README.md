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

Publish the stable Forgejo release from its CalVer tag. The **Verify Arch User
Repository packages** workflow builds the Git package from that tag and attaches
its verified `nergal_<CalVer>_linux-x64.tar.gz` and `SHA256SUMS`. It then
downloads and verifies the published archive, builds the binary package, checks
installation of both variants, and attaches `nergal-aur-recipes.zip`. The
recipe archive contains `PKGBUILD`, `.SRCINFO`, and `LICENSE` for each variant.
The binary recipe pins that release's exact archive and checksum. The Git recipe
records the version computed from the tested release commit and resolves current
Forgejo `main` on future builds. Each release keeps its own recipe archive,
including backfills. A retry preserves published assets and resumes an
interrupted archive upload when its existing files match the build.

Run the workflow on demand to build against current Git `main` and prepare a
fresh `nergal-aur-recipes` CI artifact with the latest stable binary release.
For AUR submission, review and copy the matching recipe directory into its AUR
Git repository, then follow the [AUR submission
guidelines](https://wiki.archlinux.org/title/AUR_submission_guidelines). A
`nergal-git` commit is warranted when recipe metadata or build logic changes.

On Arch, maintainers can prepare the same binary update locally by running
`python deploy/aur/update-bin.py` in a Nergal checkout. Pass a local
`nergal-bin` AUR checkout as the optional directory argument to update its
`PKGBUILD` and `.SRCINFO` directly. Pass `--tag` to select a specific published
stable release. A release without the expected archive or a matching checksum
causes the update to fail.

For `nergal-git`, update the SDK source URL and SHA-512 alongside a change to
`global.json`. Use the [Microsoft .NET release
metadata](https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json)
and regenerate `.SRCINFO` with `makepkg --printsrcinfo > .SRCINFO` when recipe
metadata changes. Each install rebuilds from Git with locked NuGet dependencies.
