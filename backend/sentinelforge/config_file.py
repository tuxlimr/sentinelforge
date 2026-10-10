"""`sentinelforge.yaml`: the project config that points SentinelForge at your own application.

Configuration is untrusted input, so it is validated strictly:

- unknown keys are errors at every level, so a typo in a safety setting can never be silently ignored
- authorization is never inferred: an http target needs `authorization_confirmed: true` and its host in `allowed_hosts`
- secrets never live in the file: sensitive headers must reference environment variables, e.g. "Bearer ${APP_TOKEN}"
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .models import DEFAULT_PACKS, Limits, RunRequest, Scope, TargetSpec

MAX_CONFIG_BYTES = 256_000
ENV_REFERENCE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
SENSITIVE_HEADER = re.compile(r"authorization|cookie|token|secret|key|password|session", re.IGNORECASE)


class ConfigError(Exception):
    """The config file is missing, malformed, or unsafe. Message is safe to show (never contains secret values)."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TargetConfig(_Strict):
    kind: Literal["http", "vulnerable_demo", "safe_demo"]
    name: str | None = None
    url: str | None = None
    headers: dict[str, str] = {}


class ScopeConfig(_Strict):
    authorization_confirmed: bool = False
    allowed_hosts: list[str] = []
    allowed_tools: list[str] = Scope().allowed_tools
    canaries: list[str] = Scope().canaries


class LimitsConfig(_Strict, Limits):
    pass


class TestsConfig(_Strict):
    __test__ = False  # not a pytest class
    packs: list[str] = Field(default_factory=lambda: list(DEFAULT_PACKS))


class CiConfig(_Strict):
    fail_on: Literal["critical", "high", "medium", "low", "informational"] = "high"


class ProjectConfig(_Strict):
    version: Literal[1]
    target: TargetConfig
    scope: ScopeConfig = ScopeConfig()
    limits: LimitsConfig = LimitsConfig()
    tests: TestsConfig = TestsConfig()
    ci: CiConfig = CiConfig()

    def run_request(self, label: str | None = None) -> RunRequest:
        """The engine request, with environment variables expanded into headers."""
        return RunRequest(target=self.target_spec(), scope=self.scope_model(),
                          limits=Limits(**self.limits.model_dump()), packs=self.tests.packs, label=label)

    def target_spec(self) -> TargetSpec:
        return TargetSpec(kind=self.target.kind, name=self.target.name, url=self.target.url,
                          headers={name: _expand(name, value) for name, value in self.target.headers.items()})

    def scope_model(self) -> Scope:
        return Scope(**self.scope.model_dump())


def _expand(header: str, value: str) -> str:
    def lookup(match: re.Match) -> str:
        name = match.group(1)
        if name not in os.environ:
            raise ConfigError(f"Header '{header}' references ${{{name}}}, but that environment variable is not set.")
        return os.environ[name]

    return ENV_REFERENCE.sub(lookup, value)


def _check(config: ProjectConfig) -> None:
    target = config.target
    if target.kind == "http" and not target.url:
        raise ConfigError("target.url is required when target.kind is http.")
    if target.kind != "http" and (target.url or target.headers):
        raise ConfigError(f"target.url and target.headers only apply to http targets, not {target.kind}.")
    for name, value in target.headers.items():
        if SENSITIVE_HEADER.search(name) and not ENV_REFERENCE.search(value):
            raise ConfigError(f"Header '{name}' looks sensitive. Put the secret in an environment variable and "
                              f"reference it, e.g. {name}: \"Bearer ${{APP_TOKEN}}\". Never commit secrets to the config.")


def load_config(path: Path) -> ProjectConfig:
    if not path.is_file():
        raise ConfigError(f"Config file {path} not found. Create one with `sentinelforge init`.")
    if path.stat().st_size > MAX_CONFIG_BYTES:
        raise ConfigError(f"Config file {path} is larger than {MAX_CONFIG_BYTES // 1000} KB; refusing to read it.")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))  # safe_load: no arbitrary Python objects
    except yaml.YAMLError as error:
        raise ConfigError(f"{path} is not valid YAML: {error}") from error
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must be a YAML mapping with at least `version: 1` and a `target`.")
    try:
        config = ProjectConfig.model_validate(data)
    except ValidationError as error:
        problems = "; ".join(f"{'.'.join(str(p) for p in e['loc']) or 'config'}: {e['msg']}" for e in error.errors())
        raise ConfigError(f"{path} is invalid: {problems}") from None  # no input echo: values may be secrets
    _check(config)
    return config


STARTER = """\
# SentinelForge project config. Docs: https://github.com/tuxlimr/sentinelforge#testing-your-own-app
version: 1

target:
{target}

scope:
  # Set to true only once you have confirmed you own this app or are authorized to test it.
  authorization_confirmed: {authorized}
  allowed_hosts: [{hosts}]
  allowed_tools: [search_docs]        # tools your agent may call; anything else is a finding

limits:
  max_cases: 30
  timeout_seconds: 10
  verify_repeats: 2                   # re-runs that must also fail before a finding is "confirmed"

tests:
  packs: [prompt_injection, canary_leakage, tool_permissions]

ci:
  fail_on: high                       # lowest severity that fails the build
"""

HTTP_TARGET = """\
  kind: http
  name: {name}
  url: {url}
  # Your endpoint receives POST {{"prompt": str, "context": {{...}}}} and returns
  # {{"text": str, "tool_calls": [{{"name": str, "args": {{}}}}]}} (plain text also works).
  # headers:
  #   Authorization: "Bearer ${{APP_TOKEN}}"   # secrets come from environment variables only"""

DEMO_TARGET = """\
  kind: safe_demo                     # replace with your app:
  # kind: http
  # url: https://your-app.example.com/api/ask
  # headers:
  #   Authorization: "Bearer ${APP_TOKEN}\""""


def starter_config(url: str | None) -> str:
    if not url:
        return STARTER.format(target=DEMO_TARGET, authorized="false", hosts="")
    from urllib.parse import urlparse

    host = urlparse(url).hostname
    if urlparse(url).scheme not in ("http", "https") or not host:
        raise ConfigError("--url must be a full http(s) URL, e.g. https://your-app.example.com/api/ask")
    return STARTER.format(target=HTTP_TARGET.format(name=json.dumps(host), url=json.dumps(url)), authorized="false", hosts=json.dumps(host))  # JSON strings are valid, injection-proof YAML
