from ..demo import safe_app, vulnerable_app
from ..models import Scope, TargetSpec
from .base import ScopeError, Target, TargetError, TargetReply
from .callable_target import CallableTarget
from .http_target import HttpTarget


def build_target(spec: TargetSpec, scope: Scope) -> Target:
    """Create the adapter for a target spec."""
    if spec.kind == "vulnerable_demo":
        return CallableTarget("vulnerable-demo", vulnerable_app.ask)
    if spec.kind == "safe_demo":
        return CallableTarget("safe-demo", safe_app.ask)
    return HttpTarget(spec, scope)


__all__ = ["ScopeError", "Target", "TargetError", "TargetReply", "build_target"]
