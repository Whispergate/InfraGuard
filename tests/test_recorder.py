"""Tests for EventRecorder structured concurrency - task lifecycle and cleanup."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from infraguard.models.events import RequestEvent
from infraguard.tracking.recorder import EventRecorder


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_event(**kwargs) -> RequestEvent:
    defaults = dict(
        timestamp=datetime.now(timezone.utc),
        domain="test.local",
        client_ip="1.2.3.4",
        method="GET",
        uri="/test",
        user_agent="TestAgent/1.0",
        filter_result="allow",
        filter_reason=None,
        filter_score=0.1,
        response_status=200,
        duration_ms=5.0,
    )
    defaults.update(kwargs)
    return RequestEvent(**defaults)


class MockPlugin:
    """Plugin that succeeds immediately."""

    name = "mock_plugin"

    def __init__(self):
        self.events: list[RequestEvent] = []

    async def on_event(self, event: RequestEvent) -> None:
        self.events.append(event)

    async def on_startup(self) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass


class FailingPlugin:
    """Plugin whose on_event always raises."""

    name = "failing_plugin"

    async def on_event(self, event: RequestEvent) -> None:
        raise ValueError("plugin error")

    async def on_startup(self) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass


class HangingPlugin:
    """Plugin that hangs forever on on_event."""

    name = "hanging_plugin"

    async def on_event(self, event: RequestEvent) -> None:
        await asyncio.sleep(9999)

    async def on_startup(self) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Test 1: record() adds flush task to tracked set
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_record_flush_task_tracked():
    """record() triggers a batch flush task that is added to _tasks."""
    db = AsyncMock()
    db.executemany = AsyncMock()
    recorder = EventRecorder(db, batch_size=1, flush_interval=60.0)

    event = make_event()
    recorder.record(event)

    # With batch_size=1 a flush task should have been created
    assert len(recorder._tasks) >= 1, "Expected at least one task in _tasks after triggering a batch flush"

    # Clean up
    for task in list(recorder._tasks):
        task.cancel()
    if recorder._tasks:
        await asyncio.gather(*recorder._tasks, return_exceptions=True)


# ---------------------------------------------------------------------------
# Test 2: record() adds plugin dispatch tasks to tracked set
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_record_plugin_tasks_tracked():
    """record() dispatches plugin tasks into _tasks."""
    db = AsyncMock()
    db.executemany = AsyncMock()
    plugin = MockPlugin()
    recorder = EventRecorder(db, batch_size=100, flush_interval=60.0, plugins=[plugin])

    event = make_event()
    recorder.record(event)

    # Plugin task should be in tracked set
    assert len(recorder._tasks) >= 1, "Expected at least one plugin task in _tasks"

    # Allow tasks to complete
    await asyncio.sleep(0.05)
    # After completion, done callback removes tasks from set
    assert len(recorder._tasks) == 0


# ---------------------------------------------------------------------------
# Test 3: stop() cancels all tracked tasks and waits for completion
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stop_cancels_all_tracked_tasks():
    """stop() cancels every task in _tasks and waits for them."""
    db = AsyncMock()
    db.executemany = AsyncMock()
    recorder = EventRecorder(db, batch_size=100, flush_interval=60.0)
    await recorder.start()

    # Inject a slow background task
    slow_task = asyncio.create_task(asyncio.sleep(9999))
    recorder._tasks.add(slow_task)
    slow_task.add_done_callback(recorder._task_done)

    assert len(recorder._tasks) >= 1

    await recorder.stop()

    # All tasks should be cancelled/gone
    assert slow_task.cancelled()
    assert len(recorder._tasks) == 0


# ---------------------------------------------------------------------------
# Test 4: Failed plugin task logs error but does not crash the recorder
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_failed_plugin_task_logs_error_no_crash():
    """Exception in a plugin task logs an error without crashing EventRecorder."""
    db = AsyncMock()
    db.executemany = AsyncMock()
    plugin = FailingPlugin()
    recorder = EventRecorder(db, batch_size=100, flush_interval=60.0, plugins=[plugin])

    event = make_event()
    # Should not raise
    recorder.record(event)

    # Wait for plugin task to complete (and fail)
    await asyncio.sleep(0.05)

    # After done callback, task is removed from set
    assert len(recorder._tasks) == 0, "Failed task should have been removed via done callback"


# ---------------------------------------------------------------------------
# Test 5: Task timeout wrapper cancels a hanging plugin after timeout
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hanging_plugin_cancelled_by_timeout():
    """A plugin that hangs is cancelled when the per-task timeout expires."""
    db = AsyncMock()
    db.executemany = AsyncMock()
    plugin = HangingPlugin()
    recorder = EventRecorder(db, batch_size=100, flush_interval=60.0, plugins=[plugin])
    recorder._task_timeout = 0.05  # very short timeout for testing

    event = make_event()
    recorder.record(event)

    # Allow enough time for the timeout to fire
    await asyncio.sleep(0.2)

    # Task should have been removed via done callback after timeout
    assert len(recorder._tasks) == 0, "Hanging plugin task should be gone after timeout"


# ---------------------------------------------------------------------------
# Test 6: Completed tasks are automatically removed via done callback
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_completed_tasks_removed_via_done_callback():
    """Done tasks are removed from _tasks by the done callback."""
    db = AsyncMock()
    db.executemany = AsyncMock()
    plugin = MockPlugin()
    recorder = EventRecorder(db, batch_size=100, flush_interval=60.0, plugins=[plugin])

    event = make_event()
    recorder.record(event)

    # Task is in set immediately after record()
    initial_count = len(recorder._tasks)
    assert initial_count >= 1, "Expected task in _tasks immediately after record()"

    # Wait for completion
    await asyncio.sleep(0.05)

    # Done callback should have cleaned it up
    assert len(recorder._tasks) == 0, "Completed task should have been removed via done callback"
