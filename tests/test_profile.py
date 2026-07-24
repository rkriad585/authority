"""Tests for authority Custom Profile."""

from __future__ import annotations

from authority.core import AuthManager


class TestProfile:
    def test_get_profile_empty(self, auth_manager: AuthManager, verified_user: dict):
        profile = auth_manager.get_profile(verified_user["id"])
        assert profile == {}

    def test_update_profile(self, auth_manager: AuthManager, verified_user: dict):
        result = auth_manager.update_profile(
            verified_user["id"],
            {"theme": "dark", "language": "en"},
        )
        assert result == {"theme": "dark", "language": "en"}

    def test_get_profile(self, auth_manager: AuthManager, verified_user: dict):
        auth_manager.update_profile(
            verified_user["id"],
            {"theme": "dark"},
        )
        profile = auth_manager.get_profile(verified_user["id"])
        assert profile == {"theme": "dark"}

    def test_update_profile_merges(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        auth_manager.update_profile(
            verified_user["id"],
            {"theme": "dark", "language": "en"},
        )
        auth_manager.update_profile(
            verified_user["id"],
            {"theme": "light"},
        )
        profile = auth_manager.get_profile(verified_user["id"])
        assert profile == {"theme": "light", "language": "en"}

    def test_update_profile_adds_new_fields(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        auth_manager.update_profile(
            verified_user["id"],
            {"theme": "dark"},
        )
        auth_manager.update_profile(
            verified_user["id"],
            {"notifications": True},
        )
        profile = auth_manager.get_profile(verified_user["id"])
        assert profile == {"theme": "dark", "notifications": True}
