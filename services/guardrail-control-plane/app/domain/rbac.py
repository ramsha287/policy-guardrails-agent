"""Roles and permissions for the control-plane API.

A principal is an admin API key. Platform keys (tenant_id = None) act on everything; tenant
keys only see and change their own tenant's catalog, tenant/agent-scoped assignments and
review queue. Publishing snapshots and the guardrail registry are platform-only because a
snapshot covers every tenant in an environment.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Permission(str, Enum):
    READ = "read"
    CATALOG_WRITE = "catalog:write"
    REGISTRY_WRITE = "registry:write"
    ASSIGNMENTS_WRITE = "assignments:write"
    PUBLISH_REQUEST = "publish:request"
    PUBLISH_APPROVE = "publish:approve"
    REVIEWS_DECIDE = "reviews:decide"
    REVIEWS_RAW = "reviews:raw"
    ADMIN_KEYS = "admin-keys:write"


ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "viewer": frozenset({Permission.READ}),
    "reviewer": frozenset({Permission.READ, Permission.REVIEWS_DECIDE}),
    "reviewer-raw": frozenset({Permission.READ, Permission.REVIEWS_DECIDE, Permission.REVIEWS_RAW}),
    "editor": frozenset(
        {Permission.READ, Permission.CATALOG_WRITE, Permission.ASSIGNMENTS_WRITE, Permission.PUBLISH_REQUEST}
    ),
    "admin": frozenset(
        {
            Permission.READ,
            Permission.CATALOG_WRITE,
            Permission.REGISTRY_WRITE,
            Permission.ASSIGNMENTS_WRITE,
            Permission.PUBLISH_REQUEST,
            Permission.PUBLISH_APPROVE,
            Permission.REVIEWS_DECIDE,
            Permission.ADMIN_KEYS,
        }
    ),
}
ROLES = frozenset(ROLE_PERMISSIONS)
PLATFORM_ONLY = frozenset({Permission.REGISTRY_WRITE, Permission.PUBLISH_REQUEST, Permission.PUBLISH_APPROVE})


class Forbidden(Exception):
    pass


@dataclass(frozen=True)
class Principal:
    key_id: str
    name: str
    roles: frozenset[str]
    tenant_id: str | None = None  # None = platform

    @property
    def actor(self) -> str:
        return f"{self.name} ({self.key_id[:8]})"

    @property
    def is_platform(self) -> bool:
        return self.tenant_id is None

    def permissions(self) -> frozenset[Permission]:
        perms: set[Permission] = set()
        for role in self.roles:
            perms |= ROLE_PERMISSIONS.get(role, frozenset())
        return frozenset(perms)

    def can(self, permission: Permission, tenant_id: str | None = None) -> bool:
        if permission not in self.permissions():
            return False
        if self.is_platform:
            return True
        if permission in PLATFORM_ONLY:
            return False
        # Tenant keys act only inside their tenant; tenant_id=None means a platform-wide object.
        return tenant_id is not None and tenant_id == self.tenant_id

    def require(self, permission: Permission, tenant_id: str | None = None) -> None:
        if not self.can(permission, tenant_id):
            scope = f" for tenant {tenant_id}" if tenant_id else ""
            raise Forbidden(f"{self.name} lacks {permission.value}{scope}")

    def visible_tenant(self, tenant_id: str) -> bool:
        return self.is_platform or self.tenant_id == tenant_id


SYSTEM = Principal(key_id="system", name="system", roles=frozenset({"admin"}))
