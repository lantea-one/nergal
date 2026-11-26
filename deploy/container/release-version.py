"""Resolve the project CalVer and the newest complete image pair in the registry."""

from base64 import b64encode
from datetime import date
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from xml.etree import ElementTree


CALVER = re.compile(r"([0-9]{4})\.([0-9]{1,2})\.([0-9]{1,2})(?:\.(0|[1-9][0-9]*))?")
NEXT_PAGE = re.compile(r'^\s*<([^>]+)>\s*;\s*rel="next"\s*$')


def calver_key(tag):
    match = CALVER.fullmatch(tag) if len(tag) <= 128 else None
    if not match:
        return None
    year, month, day, revision = match.groups()
    try:
        release_date = date(int(year), int(month), int(day))
    except ValueError:
        return None
    return release_date, int(revision or 0), tag


def project_version(ref=None):
    properties = Path(__file__).resolve().parents[2] / "Directory.Build.props"
    version = ElementTree.parse(properties).findtext("./PropertyGroup/Version")
    if not version or calver_key(version) is None:
        raise ValueError("Project Version must be a CalVer, such as 2026.11.21.1")
    if ref is not None:
        tag = ref.removeprefix("refs/tags/").removeprefix("v")
        if not ref.startswith("refs/tags/") or tag != version:
            raise ValueError(f"Release tag must match project Version {version}, with an optional v prefix")
    return version


def latest_complete(controller_tags, agent_tags):
    candidates = filter(None, map(calver_key, controller_tags & agent_tags))
    newest = max(candidates, default=None)
    if newest is None:
        raise ValueError("The registry has no CalVer present for both images")
    return newest[2]


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def registry_tags(server, image, opener, authorization):
    path = f"/v2/{image}/tags/list"
    url = server.rstrip("/") + path + "?n=100"
    origin = urlsplit(server)
    seen = set()
    tags = set()
    while url:
        target = urlsplit(url)
        if (target.scheme, target.netloc, target.path) != (origin.scheme, origin.netloc, path) or url in seen:
            raise ValueError("Invalid registry pagination link")
        seen.add(url)
        with opener.open(Request(url, headers={"Authorization": authorization}), timeout=20) as response:
            page = json.load(response)["tags"]
            if page is not None:
                if not isinstance(page, list) or any(not isinstance(tag, str) for tag in page):
                    raise ValueError("Invalid registry tag response")
                tags.update(page)
            link = response.headers.get("Link")
        if not link:
            break
        match = NEXT_PAGE.fullmatch(link)
        if not match:
            raise ValueError("Invalid registry pagination link")
        url = urljoin(url, match.group(1))
    return tags


if __name__ == "__main__":
    try:
        command, *arguments = sys.argv[1:]
        if command == "version" and len(arguments) <= 1:
            print(project_version(*arguments))
        elif command == "latest" and len(arguments) == 2:
            server, repository = arguments
            login = f"{os.environ['REGISTRY_USERNAME']}:{os.environ['REGISTRY_TOKEN']}"
            authorization = "Basic " + b64encode(login.encode()).decode()
            opener = build_opener(NoRedirect())
            controller, agent = (registry_tags(server, f"{repository}/{role}", opener, authorization)
                                 for role in ("controller", "agent"))
            print(latest_complete(controller, agent))
        else:
            raise ValueError("Use version [REF] or latest SERVER REPOSITORY")
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from None
