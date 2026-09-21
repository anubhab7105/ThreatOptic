"""Queue abstraction: bounded thread-safe queue; Kafka when KAFKA_BOOTSTRAP set.

Step 5 hardening:
- bounded (SMTP_QUEUE_MAX, default 1000): put_nowait raises queue.Full
  instead of growing without limit; the SMTP handler answers 452.
- one shared Kafka producer (created lazily, guarded by a lock) instead
  of connect-per-message; failures fall back to memory, never silent-drop
  without a log record.
- graceful shutdown: set_shutdown() wakes all blocking getters.
"""
import asyncio
import base64
import json
import logging
import queue
import threading
from typing import Any

log = logging.getLogger("queue")

_mem_queue: queue.Queue = queue.Queue()
_shutdown = threading.Event()

_producer = None
_producer_lock = threading.Lock()


def _maxsize() -> int:
    try:
        from ...config import get_settings
        return max(1, int(get_settings().smtp_queue_max or 1000))
    except Exception:
        return 1000


def _ensure_capacity() -> None:
    want = _maxsize()
    if _mem_queue.maxsize != want:
        _mem_queue.maxsize = want


def set_shutdown() -> None:
    """Wake blocking consumers so lifespan shutdown never hangs."""
    _shutdown.set()


def is_shutting_down() -> bool:
    return _shutdown.is_set()


def _get_producer():
    """Process-wide singleton Kafka producer (lazy)."""
    global _producer
    from ...config import get_settings
    settings = get_settings()
    if not settings.kafka_bootstrap:
        return None
    with _producer_lock:
        if _producer is None:
            from aiokafka import AIOKafkaProducer
            _producer = AIOKafkaProducer(bootstrap_servers=settings.kafka_bootstrap)
        return _producer


def _json_safe(payload: dict[str, Any]) -> bytes:
    def _default(o):
        if isinstance(o, (bytes, bytearray)):
            return {"__bytes_b64__": base64.b64encode(bytes(o)).decode("ascii")}
        return str(o)
    return json.dumps(payload, default=_default).encode()


async def enqueue_email(payload: dict[str, Any]) -> None:
    from ...config import get_settings
    settings = get_settings()
    if settings.kafka_bootstrap:
        producer = _get_producer()
        if producer is not None:
            try:
                await producer.start()
                try:
                    await producer.send_and_wait(settings.kafka_topic, _json_safe(payload))
                    return
                finally:
                    pass  # singleton lives on; closed at shutdown
            except Exception as e:
                log.warning("kafka publish failed, falling back to memory: %s", type(e).__name__)
    _ensure_capacity()
    try:
        _mem_queue.put_nowait(payload)
    except queue.Full:
        log.warning("ingest queue full (%s), rejecting", _mem_queue.maxsize)
        raise


async def dequeue_email() -> dict[str, Any]:
    while not is_shutting_down():
        try:
            return await asyncio.to_thread(_mem_queue.get, True, 0.5)
        except queue.Empty:
            continue
    raise asyncio.CancelledError()


def queue_depth() -> int:
    return _mem_queue.qsize()


async def close_producer() -> None:
    global _producer
    with _producer_lock:
        producer, _producer = _producer, None
    if producer is not None:
        try:
            await producer.stop()
        except Exception:
            pass
