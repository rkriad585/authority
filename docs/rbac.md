# RBAC (Roles & Permissions)

Authority ships role-based access control with a standard model:

```
permission ──< role ──< user
```

Users gain **effective permissions** as the union across all of their roles.
Roles can also inherit permission groups through permission-to-role
assignments; there is no role hierarchy — everything is flat.

## Permissions

A permission is a unique, semantic code such as `posts:read` or `admin.access`.

```python
perm = auth.create_permission("posts:read", "Can read posts")
auth.delete_permission(perm["id"])
auth.list_permissions()
```

## Roles

A role is a named bundle of permissions.

```python
role = auth.create_role("editor", "Can edit published posts")

# Grant a permission to a role
auth.assign_permission_to_role(role["id"], perm["id"])
auth.remove_permission_from_role(role["id"], perm["id"])
auth.get_role_permissions(role["id"])

auth.list_roles()
auth.delete_role(role["id"])
```

## Assigning roles to users

```python
auth.assign_role_to_user(user_id=user["id"], role_id=role["id"])
auth.remove_role_from_user(user_id=user["id"], role_id=role["id"])
auth.get_user_roles(user_id=user["id"])
```

New users are automatically assigned the role named by `default_user_role`
(`"user"` by default) on registration, if that role exists.

## Checking permissions

```python
# Boolean check
if auth.has_permission(user_id=user["id"], permission_code="posts:read"):
    ...

# Raise InsufficientPermissionsError when missing
auth.require_permission(user_id=user["id"], permission_code="posts:read")

# All permission codes the user has (deduplicated, union across roles)
auth.get_user_permissions(user_id=user["id"])
```

## Events

RBAC mutations emit lifecycle events — `RBAC_ROLE_ASSIGNED` and
`RBAC_ROLE_REVOKED` — for audit or real-time re-synchronization. See
[Events](events.md).

## Framework integrations

`require_permission(code)` and `require_role(name)` are exposed as
dependencies/decorators in the [framework integrations](integrations.md)
(FastAPI, Flask, Django, Starlette) and raise 401/403 responses instead of
exceptions.

Method signatures live on the [AuthManager](auth-manager.md) /
[AsyncAuthManager](async-auth-manager.md) pages.
