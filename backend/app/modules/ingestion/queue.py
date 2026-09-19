"""Queue abstraction: in-memory asyncio queue; Kafka when KAFKA_BOOTSTRAP set."""
import asyncio
import json
from typing import Any

_mem_queue: asyncio.Queue = asyncio.Queue()


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
    await _mem_queue.put(payload)


async def dequeue_email() -> dict[str, Any]:
    return await _mem_queue.get()


def queue_depth() -> int:
    return _mem_queue.qsize()
