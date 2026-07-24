"""Tests for authority.events."""

from __future__ import annotations

from authority.events import Event, EventBus


class TestEventBus:
    def test_on_and_emit(self):
        bus = EventBus()
        received = []
        bus.on(Event.USER_REGISTERED, lambda data: received.append(data))
        bus.emit(Event.USER_REGISTERED, {"user_id": 1})
        assert received == [{"user_id": 1}]

    def test_multiple_handlers(self):
        bus = EventBus()
        results = []
        bus.on(Event.USER_LOGIN_SUCCESS, lambda d: results.append("a"))
        bus.on(Event.USER_LOGIN_SUCCESS, lambda d: results.append("b"))
        bus.emit(Event.USER_LOGIN_SUCCESS, {})
        assert results == ["a", "b"]

    def test_off_removes_handler(self):
        bus = EventBus()
        results = []

        def handler(d):
            results.append("x")

        bus.on(Event.USER_LOGOUT, handler)
        bus.emit(Event.USER_LOGOUT, {})
        assert results == ["x"]
        bus.off(Event.USER_LOGOUT, handler)
        bus.emit(Event.USER_LOGOUT, {})
        assert results == ["x"]  # Not called again

    def test_off_nonexistent_handler_no_error(self):
        bus = EventBus()
        bus.off(Event.USER_DELETED, lambda d: None)  # Should not raise

    def test_emit_empty_data(self):
        bus = EventBus()
        received = []
        bus.on(Event.USER_DELETED, lambda d: received.append(d))
        bus.emit(Event.USER_DELETED)
        assert received == [{}]

    def test_string_event_names(self):
        bus = EventBus()
        received = []
        bus.on("custom.event", lambda d: received.append(d))
        bus.emit("custom.event", {"key": "val"})
        assert received == [{"key": "val"}]

    def test_clear(self):
        bus = EventBus()
        results = []
        bus.on(Event.USER_REGISTERED, lambda d: results.append(1))
        bus.clear()
        bus.emit(Event.USER_REGISTERED, {})
        assert results == []

    def test_handler_exception_does_not_propagate(self):
        bus = EventBus()

        def bad_handler(data):
            raise RuntimeError("oops")

        results = []
        bus.on(Event.USER_LOGIN_SUCCESS, bad_handler)
        bus.on(Event.USER_LOGIN_SUCCESS, lambda d: results.append("ok"))
        bus.emit(Event.USER_LOGIN_SUCCESS, {})
        assert results == ["ok"]  # Second handler still ran


class TestEventEnum:
    def test_events_are_strings(self):
        assert isinstance(Event.USER_REGISTERED.value, str)
        assert Event.USER_REGISTERED == "user.registered"

    def test_all_events_have_dotted_format(self):
        for event in Event:
            assert "." in event.value, f"Event {event.name} should use dotted format"
