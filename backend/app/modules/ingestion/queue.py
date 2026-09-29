
import asyncio
import base64
import json
import logging
import queue
import threading
from typing import Any

log = logging.getLogger("queue")

_mem_queue: queue.Queue = queue.Queue()

_producer = None
_producer_lock = threading.Lock()
_producer_started = False


_budget_lock = threading.Lock()
_mem_bytes = 0
_inflight = 0


def _maxsize() -> int:
    try:
        from ...config import get_settings
        return max(1, int(get_settings().smtp_queue_max or 1000))
    except Exception:
        return 1000


def _max_bytes() -> int:
    try:
        from ...config import get_settings
        return max(1024, int(get_settings().smtp_queue_max_bytes or 100 * 1024 * 1024))
    except Exception:
        return 100 * 1024 * 1024


def _ensure_capacity() -> None:
    want = _maxsize()
    if _mem_queue.maxsize != want:
        _mem_queue.maxsize = want


def _payload_bytes(payload: dict[str, Any]) -> int:
    try:
        raw = payload.get("raw", b"")
        if isinstance(raw, (bytes, bytearray)):
            return len(raw) + 1024
        return len(str(raw).encode("utf-8", "ignore")) + 1024
    except Exception:
        return 4096


def queue_bytes() -> int:
    with _budget_lock:
        return _mem_bytes


def queue_inflight() -> int:
    with _budget_lock:
        return _inflight


def _get_producer():

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


async def _get_started_producer():

    global _producer_started
    producer = _get_producer()
    if producer is None:
        return None
    if _producer_started:
        return producer
    try:
        await producer.start()
    except Exception as e:
        if "already started" not in str(e).lower():
            raise
    _producer_started = True
    return producer


def _json_safe(payload: dict[str, Any]) -> bytes:
    def _default(o):
        if isinstance(o, (bytes, bytearray)):
            return {"__bytes_b64__": base64.b64encode(bytes(o)).decode("ascii")}
        return str(o)
    return json.dumps(payload, default=_default).encode()


async def enqueue_email(payload: dict[str, Any]) -> None:
    global _mem_bytes
    from ...config import get_settings
    settings = get_settings()

    _ensure_capacity()
    size = _payload_bytes(payload)
    with _budget_lock:
        if _mem_queue.qsize() == 0:
            _mem_bytes = 0
        if _mem_bytes + size > _max_bytes():
            log.warning("ingest queue byte budget exceeded (%s+%s), rejecting", _mem_bytes, size)
            raise queue.Full
        try:
            _mem_queue.put_nowait(payload)
        except queue.Full:
            log.warning("ingest queue full (%s items), rejecting", _mem_queue.maxsize)
            raise
        _mem_bytes += size

    if settings.kafka_bootstrap:
        try:
            producer = await _get_started_producer()
            if producer is not None:
                await producer.send_and_wait(settings.kafka_topic, _json_safe(payload))
        except Exception as e:
            log.warning("kafka mirror publish failed (primary queue unaffected): %s", type(e).__name__)


async def dequeue_email() -> dict[str, Any]:




    global _mem_bytes, _inflight
    while True:
        try:
            payload = _mem_queue.get_nowait()
        except queue.Empty:
            await asyncio.sleep(0.05)
            continue
        with _budget_lock:
            _mem_bytes = max(0, _mem_bytes - _payload_bytes(payload))
            _inflight += 1
        return payload


def ack_email() -> None:

    global _inflight
    with _budget_lock:
        _inflight = max(0, _inflight - 1)


def queue_depth() -> int:
    return _mem_queue.qsize()


async def close_producer() -> None:
    global _producer, _producer_started
    with _producer_lock:
        producer, _producer = _producer, None
        _producer_started = False
    if producer is not None:
        try:
            await producer.stop()
        except Exception as e:
            log.warning("kafka producer stop failed: %s", type(e).__name__)
