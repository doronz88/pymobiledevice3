#!/usr/bin/env python3
"""Keep the docs site's pre-versioning URLs working.

The site is published with mike: each version lives in its own directory (``11.50/``, ``latest/``,
``master/``). Links from before versioning point at the site root (``/pymobiledevice3/guides/x/``), in
the README, on PyPI and around the web. Run against a checkout of the gh-pages branch just before it
is deployed, this script

- writes a redirect at each of those addresses to the same page of the default version (``latest``,
  or ``master`` before the first versioned release), keeping any ``#anchor``;
- writes a root 404 page that redirects any other unversioned path the same way;
- copies ``llms.txt`` and ``llms-full.txt`` to the root, where agents look for them.

Nothing is committed: the files exist only in the deployed site.

Usage: python3 misc/docs_root_redirects.py SITE_DIR [--base /pymobiledevice3/]
"""

import argparse
import html
import json
import os
import shutil
from pathlib import Path

DEFAULT_ALIAS = "latest"
ROOT_FILES = ("llms.txt", "llms-full.txt")

REDIRECT_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Redirecting…</title>
<link rel="canonical" href="{href}">
<meta http-equiv="refresh" content="0; url={href}">
<script>location.replace({js_href} + location.search + location.hash);</script>
</head>
<body><a href="{href}">This page moved to {href}</a></body>
</html>
"""

NOT_FOUND_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Page not found</title>
<script>
(function () {{
  var base = {js_base}, target = {js_target}, versions = {js_versions};
  var path = location.pathname;
  if (path.indexOf(base) !== 0) return;
  var rest = path.slice(base.length);
  // A path from before the site was versioned: the same page of the default version.
  if (versions.indexOf(rest.split("/")[0]) === -1) {{
    location.replace(base + target + "/" + rest + location.search + location.hash);
  }}
}})();
</script>
</head>
<body><p>Page not found. <a href="{href}">Go to the documentation.</a></p></body>
</html>
"""


def default_version(versions: list[dict]) -> str:
    if any(DEFAULT_ALIAS in entry.get("aliases", []) for entry in versions):
        return DEFAULT_ALIAS
    # Before the first versioned release only the master branch is published.
    return versions[0]["version"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("site", type=Path, help="Checkout of the gh-pages branch")
    parser.add_argument("--base", default="/pymobiledevice3/", help="URL path the site is served under")
    args = parser.parse_args()

    site: Path = args.site
    versions = json.loads((site / "versions.json").read_text())
    target = default_version(versions)
    names = sorted({entry["version"] for entry in versions} | {a for entry in versions for a in entry["aliases"]})
    source = site / target

    redirects = 0
    for page in source.rglob("index.html"):
        relative = page.relative_to(source)
        if relative.parts[0] in names:
            continue
        destination = site / relative
        href = os.path.relpath(page.parent, destination.parent).replace(os.sep, "/") + "/"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(REDIRECT_PAGE.format(href=html.escape(href), js_href=json.dumps(href)))
        redirects += 1

    (site / "404.html").write_text(
        NOT_FOUND_PAGE.format(
            js_base=json.dumps(args.base),
            js_target=json.dumps(target),
            js_versions=json.dumps(names),
            href=html.escape(f"{args.base}{target}/"),
        )
    )
    for name in ROOT_FILES:
        if (source / name).exists():
            shutil.copyfile(source / name, site / name)

    print(f"{redirects} root redirects to {target}/, plus 404.html and {', '.join(ROOT_FILES)}")


if __name__ == "__main__":
    main()
