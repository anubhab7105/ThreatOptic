"""Queue abstraction: bounded thread-safe queue; Kafka as opt-in mirror.

P0 durability contract (read before changing):
- The in-memory queue is the PRIMARY path the pipeline consumes. It is
  bounded by item count (SMTP_QUEUE_MAX) AND byte budget
  (SMTP_QUEUE_MAX_BYTES, default 100MB): a 1000-deep queue of 10MB mails
  would otherwise OOM the worker. Overflow raises queue.Full and the SMTP
  handler answers 452 — never silent-drop, never unbounded growth.
- Kafka (KAFKA_BOOTSTRAP) is an opt-in MIRROR for external consumers, not
  the pipeline path: every mail is enqueued to memory first, then
  best-effort mirrored. (Previously a successful Kafka publish returned
  early and the mail never reached the pipeline — a black hole, since no
  consumer exists in this repo.) Mirror failures only log.
- The Kafka producer is started ONCE (start-per-enqueue silently fell back
  to memory after the first message in some client libraries).
- Consumer discipline: dequeue_email() hands one payload to exactly one
  consumer; the consumer MUST call ack_email() after finishing (success or
  failure) so queue_inflight() reflects reality. In-memory state cannot
  survive a process restart — unacked/queued mail on a crash is lost;
  cross-restart durability needs an external durable broker + consumer
  group, which is explicitly out of scope here.
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

_producer = None
_producer_lock = threading.Lock()
_producer_started = False

# Byte-budget + in-flight accounting (guarded; self-heals when empty).
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


async def _get_started_producer():
    """Singleton producer, started exactly once (P0).

    Re-awaiting start() on every enqueue made some client versions raise
    (or wedge), which the old code swallowed into a silent memory
    fallback. Concurrent first-enqueues may both call start(); the loser
    observes "already started" and proceeds.
    """
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
    # Primary path first: bounded memory queue (byte budget + item cap).
    _ensure_capacity()
    size = _payload_bytes(payload)
    with _budget_lock:
        if _mem_queue.qsize() == 0:
            _mem_bytes = 0  # self-heal if drained outside dequeue_email
        if _mem_bytes + size > _max_bytes():
            log.warning("ingest queue byte budget exceeded (%s+%s), rejecting", _mem_bytes, size)
            raise queue.Full
        try:
            _mem_queue.put_nowait(payload)
        except queue.Full:
            log.warning("ingest queue full (%s items), rejecting", _mem_queue.maxsize)
            raise
        _mem_bytes += size
    # Opt-in mirror for external consumers; never replaces the primary path.
    if settings.kafka_bootstrap:
        try:
            producer = await _get_started_producer()
            if producer is not None:
                await producer.send_and_wait(settings.kafka_topic, _json_safe(payload))
        except Exception as e:
            log.warning("kafka mirror publish failed (primary queue unaffected): %s", type(e).__name__)


async def dequeue_email() -> dict[str, Any]:
    # task.cancel() is the shutdown signal: CancelledError propagates out of
    # the sleep immediately. get_nowait (not a blocking get) means a cancel
    # can never strand an already-removed item: every returned payload is
    # exactly-once handed out and byte/inflight-accounted here.
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
    """Mark one dequeued payload finished (P0 consumer discipline).

    Call after the pipeline run completes, success or failure. Memory-only
    bookkeeping for queue_inflight(); see module docstring for the
    durability contract.
    """
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
