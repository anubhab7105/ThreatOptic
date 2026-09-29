
import copy
import json
import logging
import threading
import time

log = logging.getLogger("cache")

_mem: dict[str, tuple[float, object]] = {}
_mem_lock = threading.Lock()
_redis = None


def _redis_client():
    global _redis
    if _redis is not None:
        return _redis
    try:
        from ...config import get_settings
        url = (get_settings().redis_url or "").strip()
    except Exception:
        url = ""
    if not url:
        return None
    try:
        import redis
        _redis = redis.Redis.from_url(url, socket_timeout=3, decode_responses=True)
        _redis.ping()
        return _redis
    except Exception as e:
        log.warning("redis unavailable (%s); using in-process cache", type(e).__name__)
        return None


def backend_name() -> str:
    return "redis" if _redis_client() is not None else "memory"


def cache_get(key: str):
    r = _redis_client()
    if r is not None:
        try:
            raw = r.get(f"soc:{key}")
            return copy.deepcopy(json.loads(raw)) if raw is not None else None
        except Exception:
            return None
    with _mem_lock:
        entry = _mem.get(key)
        if entry is None:
            return None
        exp, val = entry
        if exp < time.monotonic():
            _mem.pop(key, None)
            return None
        return copy.deepcopy(val)


def cache_set(key: str, value: object, ttl: int) -> None:
    r = _redis_client()
    if r is not None:
        try:
            r.setex(f"soc:{key}", max(1, int(ttl)), json.dumps(value, default=str))
            return
        except Exception:
            pass
    with _mem_lock:
        _mem[key] = (time.monotonic() + max(1, int(ttl)), copy.deepcopy(value))


def cache_delete_prefix(prefix: str) -> int:

    r = _redis_client()
    if r is not None:
        try:
            n = 0
            for k in r.scan_iter(f"soc:{prefix}*"):
                r.delete(k)
                n += 1
            return n
        except Exception:
            return 0
    with _mem_lock:
        doomed = [k for k in _mem if k.startswith(prefix)]
        for k in doomed:
            _mem.pop(k, None)
        return len(doomed)


def cache_clear() -> None:

    global _redis
    with _mem_lock:
        _mem.clear()
