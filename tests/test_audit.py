"""Tests for authority Audit Log queries."""

from __future__ import annotations

from authority.core import AuthManager


class TestAuditLog:
    def test_audit_log_empty(self, auth_manager: AuthManager):
        logs = auth_manager.get_audit_log()
        assert logs == []

    def test_audit_log_after_register(self, auth_manager: AuthManager):
        auth_manager.register(
            name="Audit User",
            email="audit@example.com",
            password="SecureP@ss1234!",
        )
        logs = auth_manager.get_audit_log()
        assert len(logs) >= 1
        assert logs[0]["action"] == "user.registered"

    def test_audit_log_filter_by_user(self, auth_manager: AuthManager):
        user1 = auth_manager.register(
            name="User 1", email="u1@example.com", password="SecureP@ss1234!"
        )
        auth_manager.register(
            name="User 2", email="u2@example.com", password="SecureP@ss1234!"
        )
        logs = auth_manager.get_audit_log(user_id=user1["id"])
        for log in logs:
            assert log["user_id"] == user1["id"]

    def test_audit_log_filter_by_action(self, auth_manager: AuthManager):
        auth_manager.register(
            name="Test", email="test@example.com", password="SecureP@ss1234!"
        )
        logs = auth_manager.get_audit_log(action="user.registered")
        assert len(logs) >= 1
        assert all(entry["action"] == "user.registered" for entry in logs)

    def test_audit_log_pagination(self, auth_manager: AuthManager):
        for i in range(5):
            auth_manager.register(
                name=f"User {i}",
                email=f"user{i}@example.com",
                password="SecureP@ss1234!",
            )
        logs_page1 = auth_manager.get_audit_log(limit=2, offset=0)
        logs_page2 = auth_manager.get_audit_log(limit=2, offset=2)
        assert len(logs_page1) == 2
        assert len(logs_page2) == 2
        assert logs_page1[0]["id"] != logs_page2[0]["id"]
