"""Real Redis lease ownership across the executor hand-off used by batches."""

import asyncio
import os
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from app.ai.cache_lock import RedisCacheLock


@pytest.fixture
def owned_lock_key():
    if not os.getenv("AI_TEST_REDIS_URL"):
        pytest.skip("Set AI_TEST_REDIS_URL for Redis executor lease regression")
    import redis

    client = redis.Redis.from_url(os.environ["AI_TEST_REDIS_URL"])
    key = "sbo74-thread-handoff-" + uuid.uuid4().hex
    yield client, key
    client.delete("ai_fix_gen:" + key)


@pytest.mark.asyncio
@pytest.mark.parametrize("replaced", [False, True])
async def test_executor_thread_handoff_releases_only_its_own_lease(owned_lock_key, replaced):
    client, key = owned_lock_key
    redis_key = "ai_fix_gen:" + key
    loop = asyncio.get_running_loop()
    original = loop.run_in_executor
    with ThreadPoolExecutor(max_workers=1) as acquire_pool, ThreadPoolExecutor(max_workers=1) as release_pool:
        def split(executor, function, *args):
            pool = acquire_pool if function.__name__ == "acquire" else release_pool
            return original(pool, function, *args)

        # Force different threads rather than depending on scheduler luck.
        loop.run_in_executor = split
        try:
            async with RedisCacheLock(client).acquire(key, ttl_seconds=5) as acquired:
                assert acquired
                if replaced:
                    client.set(redis_key, "synthetic-new-owner", ex=5)
            if replaced:
                assert client.get(redis_key) == b"synthetic-new-owner"
            else:
                assert client.get(redis_key) is None
        finally:
            loop.run_in_executor = original
