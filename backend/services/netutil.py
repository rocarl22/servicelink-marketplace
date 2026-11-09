"""Trusted-proxy client IP handling for the web API. Stdlib only.

Never trust X-Forwarded-For blindly: it is attacker-controlled unless the
direct peer is a proxy you operate. Resolve the client by walking the header
from the right, skipping only hops that are your own proxies.
"""
import hashlib
import ipaddress
from typing import Iterable, Optional


def _parse(value: str):
    try:
        return ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None


def _in(ip, networks) -> bool:
    return any(ip in net for net in networks)


def client_ip(remote_addr: str, forwarded_for: Optional[str] = None,
              trusted_proxies: Iterable[str] = ()) -> Optional[str]:
    """Return the real client IP, or None if remote_addr is unparsable."""
    peer = _parse(remote_addr or "")
    if peer is None:
        return None
    nets = [ipaddress.ip_network(p, strict=False) for p in trusted_proxies]
    if not nets or not _in(peer, nets) or not forwarded_for:
        return str(peer)                      # untrusted peer: ignore the header
    hops = [h for h in (x.strip() for x in forwarded_for.split(",")) if h]
    for hop in reversed(hops):
        ip = _parse(hop)
        if ip is None:
            return str(peer)                  # malformed header: fall back to the peer
        if not _in(ip, nets):
            return str(ip)
    return str(peer)


def rate_bucket_ip(ip: str) -> str:
    """Group IPv6 clients by /64 (one household can own 2^64 addresses)."""
    parsed = _parse(ip or "")
    if parsed is None:
        return "unknown"
    if parsed.version == 6:
        return str(ipaddress.ip_network(f"{parsed}/64", strict=False).network_address) + "/64"
    return str(parsed)


def rate_key(prefix: str, *parts: str) -> str:
    """Hashed rate-limit key so raw phones/usernames/IPs never sit in the table."""
    digest = hashlib.sha256("\x1f".join(p.casefold() for p in parts).encode("utf-8")).hexdigest()
    return f"{prefix}:{digest}"
