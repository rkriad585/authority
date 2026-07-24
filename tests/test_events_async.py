"""Tests for EventBus async handler support."""

from __future__ import annotations

from authority.events import Event, EventBus


class TestEventBusAsyncHandlers:
    async def test_emit_async_with_async_handler(self):
        bus = EventBus()
        received: list[dict] = []

        async def handler(data: dict):
            received.append(data)

        bus.on("test.event", handler)
        await bus.emit_async("test.event", {"key": "value"})

        assert len(received) == 1
        assert received[0]["key"] == "value"

    async def test_emit_async_with_sync_handler(self):
        bus = EventBus()
        received: list[dict] = []

        def handler(data: dict):
            received.append(data)

        bus.on("test.event", handler)
        await bus.emit_async("test.event", {"key": "value"})

        assert len(received) == 1
        assert received[0]["key"] == "value"

    async def test_emit_async_handler_error_does_not_propagate(self):
        bus = EventBus()

        async def failing_handler(data: dict):
            raise ValueError("handler error")

        bus.on("test.event", failing_handler)
        # Should not raise
        await bus.emit_async("test.event", {"key": "value"})

    async def test_emit_async_multiple_handlers(self):
        bus = EventBus()
        results: list[str] = []

        async def handler_a(data: dict):
            results.append("a")

        def handler_b(data: dict):
            results.append("b")

        bus.on("test.event", handler_a)
        bus.on("test.event", handler_b)
        await bus.emit_async("test.event")

        assert results == ["a", "b"]

    def test_emit_with_async_handler_no_running_loop(self):
        """When no event loop is running, async handlers are skipped with warning."""
        bus = EventBus()
        received: list[dict] = []

        async def handler(data: dict):
            received.append(data)

        bus.on("test.event", handler)
        # Calling emit() outside of an async context — async handler should be skipped
        bus.emit("test.event", {"key": "value"})
        assert len(received) == 0

    async def test_emit_async_with_enum_event(self):
        bus = EventBus()
        received: list[dict] = []

        async def handler(data: dict):
            received.append(data)

        bus.on(Event.USER_LOGIN_SUCCESS.value, handler)
        await bus.emit_async(Event.USER_LOGIN_SUCCESS, {"user_id": 1})

        assert len(received) == 1
        assert received[0]["user_id"] == 1
