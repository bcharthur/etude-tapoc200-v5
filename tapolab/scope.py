from .config import Scope, normalize_mac


class ScopeError(RuntimeError):
    pass


def assert_mac_expected(scope: Scope, observed_mac: str | None) -> None:
    if not observed_mac:
        raise ScopeError(
            "MAC inconnue pour la cible. Lance identify/discover avant toute probe."
        )
    if normalize_mac(observed_mac) != scope.target_mac:
        raise ScopeError(
            f"MAC inattendue: {normalize_mac(observed_mac)} != {scope.target_mac}"
        )
