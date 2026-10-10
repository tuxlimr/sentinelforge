"""Recognize front-end libraries on a page and compare them to published fix versions.

Versions come from a script or stylesheet URL, or from a version banner in a same-host file.
Nothing here is an exploit. A match means that published release is in a range that has a fix.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

MAX_LIBRARY_FILES = 3
_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_QUERY_VERSION = re.compile(r"[?&]ver=(\d+)\.(\d+)\.(\d+)")
_COMMENT = re.compile(r"<!--.*?-->", re.S)
_TAG = re.compile(r"<(script|link)\b([^>]*)>", re.I)
_ATTR = re.compile(r"""([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.I)

LIMITATION = (
    "The version was read from a script or stylesheet URL, or from a version banner in a same-host file. "
    "A bundled or renamed copy can differ. A library in a known-vulnerable range is not proof this site can be exploited."
)


@dataclass(frozen=True)
class LibraryRule:
    case_id: str
    name: str
    severity: str
    identity: re.Pattern[str]
    banner: re.Pattern[str]
    risk: str
    expected: str
    mitigation: str

    def affected(self, version: tuple[int, int, int]) -> bool:
        return version < _FLOOR[self.case_id]


@dataclass(frozen=True)
class LibraryHit:
    """One library reference found in markup. `version` is None until a banner fills it in."""

    rule: LibraryRule
    version: tuple[int, int, int] | None
    source: str
    script_src: str | None = None


def _rule(case_id: str, name: str, severity: str, identity: str, banner: str, risk: str, expected: str, mitigation: str) -> LibraryRule:
    return LibraryRule(case_id, name, severity, re.compile(identity, re.I), re.compile(banner, re.I), risk, expected, mitigation)


# More specific identities first, so jquery-ui is not also reported as jQuery.
RULES: tuple[LibraryRule, ...] = (
    _rule(
        "WEB-032", "jQuery UI", "medium",
        r"(?<![A-Za-z0-9])jquery[-.]?ui(?:[-.]min)?\.js"
        r"|(?<![A-Za-z0-9])jquery[-.]ui[-@/]v?\d+\.\d+\.\d+"
        r"|/ui/\d+\.\d+\.\d+/jquery-ui",
        r"jQuery UI - v(\d+)\.(\d+)\.(\d+)",
        "jQuery UI before 1.13.2 has a publicly fixed cross-site scripting issue in the checkboxradio widget.",
        "jQuery UI 1.13.2 or later.",
        "Upgrade jQuery UI to 1.13.2 or later.",
    ),
    _rule(
        "WEB-031", "jQuery", "medium",
        r"(?<![A-Za-z0-9])jquery(?![-.]?ui)(?:[-.](?:slim|min))*\.js"
        r"|(?<![A-Za-z0-9])jquery(?![-.]?ui)[-@/]v?\d+\.\d+\.\d+"
        r"|/jquery/\d+\.\d+\.\d+/",
        r"jQuery v(\d+)\.(\d+)\.(\d+)",
        "jQuery before 3.5.0 has publicly fixed cross-site scripting issues in its HTML handling. The 1.x and 2.x lines are unsupported.",
        "jQuery 3.5.0 or later.",
        "Upgrade jQuery to 3.5.0 or later.",
    ),
    _rule(
        "WEB-033", "Bootstrap", "medium",
        r"(?<![A-Za-z0-9])bootstrap(?:\.bundle)?(?:[-.]min)?\.(?:js|css)"
        r"|(?<![A-Za-z0-9])bootstrap[-@/]v?\d+\.\d+\.\d+"
        r"|/bootstrap/\d+\.\d+\.\d+/",
        r"Bootstrap v(\d+)\.(\d+)\.(\d+)",
        "Bootstrap 3 before 3.4.1 and Bootstrap 4 before 4.3.1 have a publicly fixed cross-site scripting issue in tooltip and popover HTML handling.",
        "Bootstrap 3.4.1 or later on the 3.x line, or 4.3.1 or later on the 4.x line.",
        "Upgrade Bootstrap 3 to 3.4.1, or Bootstrap 4 to 4.3.1 or later.",
    ),
    _rule(
        "WEB-034", "Lodash", "medium",
        r"(?<![A-Za-z0-9])lodash(?:[-.]min)?\.js"
        r"|(?<![A-Za-z0-9])lodash[-@/]v?\d+\.\d+\.\d+"
        r"|/lodash/\d+\.\d+\.\d+/",
        r"lodash v?(\d+)\.(\d+)\.(\d+)",
        "Lodash before 4.18.0 has a publicly fixed prototype-pollution issue in _.unset and _.omit.",
        "Lodash 4.18.0 or later.",
        "Upgrade Lodash to 4.18.0 or later.",
    ),
    _rule(
        "WEB-035", "Moment.js", "low",
        r"(?<![A-Za-z0-9])moment(?:[-.]with[-.]locales)?(?:[-.]min)?\.js"
        r"|moment\.js/\d+\.\d+\.\d+"
        r"|(?<![A-Za-z0-9])moment[-@/]v?\d+\.\d+\.\d+",
        r"version\s*:\s*(\d+)\.(\d+)\.(\d+)",
        "Moment.js before 2.29.4 has a publicly fixed regular-expression denial-of-service issue in date parsing.",
        "Moment.js 2.29.4 or later.",
        "Upgrade Moment.js to 2.29.4 or later.",
    ),
    _rule(
        "WEB-036", "AngularJS", "medium",
        r"(?<![A-Za-z0-9])angular(?:\.min)?\.js|(?<![A-Za-z0-9])angularjs[/.-]|(?<![A-Za-z0-9])angular@1\.\d+",
        r"AngularJS v(\d+)\.(\d+)\.(\d+)",
        "AngularJS 1.x is end of life, and releases on that line have publicly fixed cross-site scripting issues.",
        "A supported framework. AngularJS 1.x no longer receives security fixes.",
        "Migrate off AngularJS 1.x. There is no supported fix release.",
    ),
)

_BY_ID = {rule.case_id: rule for rule in RULES}
_FLOOR = {"WEB-032": (1, 13, 2), "WEB-031": (3, 5, 0), "WEB-034": (4, 18, 0), "WEB-035": (2, 29, 4)}


def _attrs(raw: str) -> dict[str, str]:
    return {match.group(1).lower(): match.group(2) if match.group(2) is not None else match.group(3) for match in _ATTR.finditer(raw)}


def _version_tuple(groups: tuple[str, ...]) -> tuple[int, int, int]:
    parts = [group for group in groups if group is not None]
    return int(parts[0]), int(parts[1]), int(parts[2])


def _version_near(match: re.Match[str], value: str) -> tuple[int, int, int] | None:
    query = _QUERY_VERSION.search(value)
    if query and abs(query.start() - match.end()) < 80:
        return _version_tuple(query.groups())
    window_start = max(0, match.start() - 48)
    window = value[window_start:match.end() + 48]
    found = list(_VERSION.finditer(window))
    if not found:
        return None
    anchor = match.start() - window_start
    best = min(found, key=lambda item: abs(item.start() - anchor))
    return _version_tuple(best.groups())


def _classify(value: str) -> tuple[LibraryRule, tuple[int, int, int] | None] | None:
    for rule in RULES:
        matches = list(rule.identity.finditer(value))
        if not matches:
            continue
        matches.sort(key=lambda item: _version_near(item, value) is None)
        return rule, _version_near(matches[0], value)
    return None


def inspect_html(html: str) -> list[LibraryHit]:
    """Library references in script src and stylesheet href values. Body text and comments are ignored."""
    hits: list[LibraryHit] = []
    for tag, raw_attrs in _TAG.findall(_COMMENT.sub("", html)):
        attrs = _attrs(raw_attrs)
        if tag.lower() == "script":
            source = attrs.get("src", "")
        elif "stylesheet" in attrs.get("rel", "").lower():
            source = attrs.get("href", "")
        else:
            continue
        if not source:
            continue
        classified = _classify(source)
        if classified is None:
            continue
        rule, version = classified
        hits.append(LibraryHit(rule, version, source, source if tag.lower() == "script" and version is None else None))
    return hits


def same_host_script(src: str, page_url: str, host: str) -> str | None:
    """Absolute URL of a script on the scanned host, or None when fetching it would leave that host."""
    absolute = urljoin(page_url, src)
    parsed = urlparse(absolute)
    if parsed.scheme not in ("http", "https") or parsed.hostname != host:
        return None
    return absolute


def version_from_banner(rule: LibraryRule, text: str) -> tuple[int, int, int] | None:
    """Read a version banner from the start of a script. Moment's banner is only trusted beside its own name."""
    head = text[:2000]
    if rule.case_id == "WEB-035" and "moment.js" not in head.lower():
        return None
    match = rule.banner.search(head)
    if match is None:
        return None
    version = _version_tuple(match.groups())
    if rule.case_id == "WEB-036" and version[0] != 1:
        return None
    return version


def is_affected(rule: LibraryRule, version: tuple[int, int, int]) -> bool:
    if rule.case_id == "WEB-033":
        if version[0] == 3:
            return version < (3, 4, 1)
        if version[0] == 4:
            return version < (4, 3, 1)
        return False
    if rule.case_id == "WEB-036":
        return version[0] == 1
    return rule.affected(version)


def rule_by_id(case_id: str) -> LibraryRule:
    return _BY_ID[case_id]
