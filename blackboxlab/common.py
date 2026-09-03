from __future__ import annotations

from tapolab.config import load_scope
from tapolab.identify import identify
from tapolab.scope import assert_mac_expected


def validated_scope():
    scope = load_scope()
    data = identify(scope)
    assert_mac_expected(scope, data.get("observed_mac"))
    return scope, data
