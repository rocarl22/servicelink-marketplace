"""Authorization helpers. Stdlib only, no Qt.

Rule for every endpoint (desktop bridge today, HTTP API next): the acting
principal comes from the authenticated session, never from a caller-supplied
id. These helpers make the pair-of-accounts case explicit and testable.
"""
from typing import Callable, Optional, Tuple


def resolve_client_provider(session_account_id: str, other_account_id: str,
                            role_of: Callable[[str], str]) -> Optional[Tuple[str, str]]:
    """Return (client_id, provider_id) for a session-owned account and its counterpart.

    The role is taken from the session-owned account only, and the counterpart
    must hold the opposite role; anything else returns None (deny).
    """
    if not session_account_id or not other_account_id or session_account_id == other_account_id:
        return None
    mine, theirs = role_of(session_account_id), role_of(other_account_id)
    if mine == "client" and theirs == "provider":
        return session_account_id, other_account_id
    if mine == "provider" and theirs == "client":
        return other_account_id, session_account_id
    return None
