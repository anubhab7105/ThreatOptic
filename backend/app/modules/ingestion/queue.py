"""Queue abstraction: thread-safe in-memory queue; Kafka when KAFKA_BOOTSTRAP set.

A plain (thread-safe) queue is used instead of asyncio.Queue because the
aiosmtpd handler runs on the SMTP controller's own event loop/thread while
the consumer runs on the app loop — an asyncio.Queue would bind to one loop
and break when touched from the other.
"""
import asyncio
import json
import queue
from typing import Any

_mem_queue: queue.Queue = queue.Queue()


async def enqueue_email(payload: dict[str, Any]) -> None:
    from ...config import get_settings
    settings = get_settings()
    if settings.kafka_bootstrap:
        try:
            from aiokafka import AIOKafkaProducer
            producer = AIOKafkaProducer(bootstrap_servers=settings.kafka_bootstrap)
            await producer.start()
            try:
                await producer.send_and_wait(settings.kafka_topic, json.dumps(payload).encode())
                return
            finally:
                await producer.stop()
        except Exception:
            pass  # fall back to memory
    _mem_queue.put(payload)


async def dequeue_email() -> dict[str, Any]:
    return await asyncio.to_thread(_mem_queue.get)


def queue_depth() -> int:
    return _mem_queue.qsize()
