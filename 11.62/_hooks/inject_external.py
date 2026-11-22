"""MkDocs hook that pulls Markdown files living outside ``docs/`` into the site.

Several long-form documents (protocol write-ups under ``misc/``, the DTX docs next
to their code, and project meta files like ``CONTRIBUTING.md``) are the canonical
source and must not be duplicated. This hook injects them as generated pages at
build time and rewrites their repo-relative links to absolute GitHub URLs (or to
the corresponding in-site page when the target is also injected).
"""

from __future__ import annotations

import os
import posixpath
import re

from mkdocs.structure.files import File

REPO = "https://github.com/doronz88/pymobiledevice3/blob/master"

# disk path (relative to repo root) -> in-site uri
EXTERNAL_PAGES = {
    "misc/understanding_idevice_protocol_layers.md": "internals/idevice-protocol-layers.md",
    "misc/RemoteXPC.md": "internals/remotexpc.md",
    "pymobiledevice3/dtx/README.md": "internals/dtx.md",
    "pymobiledevice3/dtx/DEVELOPMENT.md": "internals/dtx-development.md",
    "CONTRIBUTING.md": "project/contributing.md",
    "AGENTS.md": "project/agents.md",
    "CODE_OF_CONDUCT.md": "project/code-of-conduct.md",
}

_LINK_RE = re.compile(r"(\]\()([^)]+)(\))")


def _rewrite_target(target: str, source_disk_path: str) -> str:
    """Rewrite a single Markdown link target found inside an injected page."""
    if target.startswith(("#", "http://", "https://", "mailto:")):
        return target

    path_part, _, anchor = target.partition("#")
    suffix = f"#{anchor}" if anchor else ""
    if not path_part:
        return target  # pure in-page anchor

    # Resolve the link relative to the source file's original location in the repo.
    source_dir = posixpath.dirname(source_disk_path)
    if path_part.startswith("/"):
        repo_path = posixpath.normpath(path_part.lstrip("/"))
    else:
        repo_path = posixpath.normpath(posixpath.join(source_dir, path_part))

    # If the target is another injected page, link to it inside the site (relative, so it works
    # under the GitHub Pages project subpath).
    if repo_path in EXTERNAL_PAGES:
        here = posixpath.dirname(EXTERNAL_PAGES[source_disk_path])
        return posixpath.relpath(EXTERNAL_PAGES[repo_path], here) + suffix

    # Otherwise point at the file on GitHub.
    return f"{REPO}/{repo_path}{suffix}"


def _transform(markdown: str, source_disk_path: str) -> str:
    return _LINK_RE.sub(
        lambda m: m.group(1) + _rewrite_target(m.group(2), source_disk_path) + m.group(3),
        markdown,
    )


def on_files(files, config):
    docs_dir = config["docs_dir"]
    repo_root = os.path.dirname(docs_dir)
    for disk_path, site_uri in EXTERNAL_PAGES.items():
        abs_path = os.path.join(repo_root, disk_path)
        if not os.path.exists(abs_path):
            continue
        with open(abs_path, encoding="utf-8") as fh:
            content = _transform(fh.read(), disk_path)
        files.append(File.generated(config, site_uri, content=content))
    return files
