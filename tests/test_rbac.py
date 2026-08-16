"""Tests for authority RBAC — roles, permissions, assignments."""

from __future__ import annotations

import pytest

from authority.core import AuthManager
from authority.exceptions import InsufficientPermissionsError


class TestRoles:
    def test_create_role(self, auth_manager: AuthManager):
        role = auth_manager.create_role("admin", "Administrator role")
        assert role["name"] == "admin"
        assert role["description"] == "Administrator role"
        assert "id" in role

    def test_create_role_no_description(self, auth_manager: AuthManager):
        role = auth_manager.create_role("viewer")
        assert role["name"] == "viewer"
        assert role["description"] is None

    def test_list_roles_empty(self, auth_manager: AuthManager):
        assert auth_manager.list_roles() == []

    def test_list_roles(self, auth_manager: AuthManager):
        auth_manager.create_role("admin")
        auth_manager.create_role("editor")
        roles = auth_manager.list_roles()
        assert len(roles) == 2
        names = {r["name"] for r in roles}
        assert names == {"admin", "editor"}

    def test_delete_role(self, auth_manager: AuthManager):
        role = auth_manager.create_role("temp")
        assert auth_manager.delete_role(role["id"])
        assert auth_manager.list_roles() == []


class TestPermissions:
    def test_create_permission(self, auth_manager: AuthManager):
        perm = auth_manager.create_permission("users:read", "Read users")
        assert perm["code"] == "users:read"
        assert perm["description"] == "Read users"
        assert "id" in perm

    def test_list_permissions(self, auth_manager: AuthManager):
        auth_manager.create_permission("users:read")
        auth_manager.create_permission("users:write")
        perms = auth_manager.list_permissions()
        assert len(perms) == 2

    def test_delete_permission(self, auth_manager: AuthManager):
        perm = auth_manager.create_permission("temp:perm")
        assert auth_manager.delete_permission(perm["id"])
        assert auth_manager.list_permissions() == []


class TestRolePermissionAssignment:
    def test_assign_and_remove(self, auth_manager: AuthManager):
        role = auth_manager.create_role("admin")
        perm = auth_manager.create_permission("users:manage")

        assert auth_manager.assign_permission_to_role(role["id"], perm["id"])

        role_perms = auth_manager.get_role_permissions(role["id"])
        assert len(role_perms) == 1
        assert role_perms[0]["code"] == "users:manage"

        assert auth_manager.remove_permission_from_role(role["id"], perm["id"])
        assert auth_manager.get_role_permissions(role["id"]) == []


class TestUserRoleAssignment:
    def test_assign_and_remove_role(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        role = auth_manager.create_role("admin")
        assert auth_manager.assign_role_to_user(verified_user["id"], role["id"])

        user_roles = auth_manager.get_user_roles(verified_user["id"])
        assert len(user_roles) == 1
        assert user_roles[0]["name"] == "admin"

        assert auth_manager.remove_role_from_user(verified_user["id"], role["id"])
        assert auth_manager.get_user_roles(verified_user["id"]) == []


class TestEffectivePermissions:
    def test_user_permissions_from_roles(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        role = auth_manager.create_role("editor")
        perm1 = auth_manager.create_permission("posts:read")
        perm2 = auth_manager.create_permission("posts:write")

        auth_manager.assign_permission_to_role(role["id"], perm1["id"])
        auth_manager.assign_permission_to_role(role["id"], perm2["id"])
        auth_manager.assign_role_to_user(verified_user["id"], role["id"])

        perms = auth_manager.get_user_permissions(verified_user["id"])
        assert set(perms) == {"posts:read", "posts:write"}

    def test_user_permissions_multiple_roles(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        role1 = auth_manager.create_role("reader")
        role2 = auth_manager.create_role("writer")
        perm1 = auth_manager.create_permission("posts:read")
        perm2 = auth_manager.create_permission("posts:write")

        auth_manager.assign_permission_to_role(role1["id"], perm1["id"])
        auth_manager.assign_permission_to_role(role2["id"], perm2["id"])
        auth_manager.assign_role_to_user(verified_user["id"], role1["id"])
        auth_manager.assign_role_to_user(verified_user["id"], role2["id"])

        perms = auth_manager.get_user_permissions(verified_user["id"])
        assert set(perms) == {"posts:read", "posts:write"}

    def test_has_permission(self, auth_manager: AuthManager, verified_user: dict):
        role = auth_manager.create_role("viewer")
        perm = auth_manager.create_permission("content:read")
        auth_manager.assign_permission_to_role(role["id"], perm["id"])
        auth_manager.assign_role_to_user(verified_user["id"], role["id"])

        assert auth_manager.has_permission(verified_user["id"], "content:read")
        assert not auth_manager.has_permission(verified_user["id"], "content:write")

    def test_no_permissions(self, auth_manager: AuthManager, verified_user: dict):
        assert auth_manager.get_user_permissions(verified_user["id"]) == []
        assert not auth_manager.has_permission(verified_user["id"], "anything")


class TestRequirePermission:
    def test_require_permission_passes(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        role = auth_manager.create_role("viewer")
        perm = auth_manager.create_permission("content:read")
        auth_manager.assign_permission_to_role(role["id"], perm["id"])
        auth_manager.assign_role_to_user(verified_user["id"], role["id"])

        auth_manager.require_permission(verified_user["id"], "content:read")

    def test_require_permission_denied(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        role = auth_manager.create_role("viewer")
        perm = auth_manager.create_permission("content:read")
        auth_manager.assign_permission_to_role(role["id"], perm["id"])
        auth_manager.assign_role_to_user(verified_user["id"], role["id"])

        with pytest.raises(InsufficientPermissionsError, match="content:write"):
            auth_manager.require_permission(verified_user["id"], "content:write")

    def test_require_permission_no_permissions(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        with pytest.raises(InsufficientPermissionsError):
            auth_manager.require_permission(verified_user["id"], "anything")
