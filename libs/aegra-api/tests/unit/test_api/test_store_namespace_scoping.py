"""Tests for store namespace scoping / user and org isolation."""

import pytest
from fastapi import HTTPException

from aegra_api.api.store import apply_namespace_scoping


class TestUserNamespaceScoping:
    """Verify that apply_namespace_scoping enforces per-user isolation."""

    def test_empty_namespace_defaults_to_user_prefix(self) -> None:
        result = apply_namespace_scoping([], user_id="user-123", org_id=None)
        assert result == ["users", "user-123"]

    def test_own_namespace_passes_through(self) -> None:
        ns = ["users", "user-123", "documents"]
        result = apply_namespace_scoping(ns, user_id="user-123", org_id=None)
        assert result == ["users", "user-123", "documents"]

    def test_own_namespace_exact_passes_through(self) -> None:
        ns = ["users", "user-123"]
        result = apply_namespace_scoping(ns, user_id="user-123", org_id=None)
        assert result == ["users", "user-123"]

    def test_other_user_namespace_is_scoped(self) -> None:
        """A user cannot access another user's namespace — it gets remapped."""
        ns = ["users", "victim-456", "secrets"]
        result = apply_namespace_scoping(ns, user_id="user-123", org_id=None)
        assert result == ["users", "user-123", "users", "victim-456", "secrets"]
        assert result != ns

    def test_other_user_namespace_no_passthrough(self) -> None:
        """Ensure attacker-supplied namespace for another user is never returned as-is."""
        ns = ["users", "victim-456"]
        result = apply_namespace_scoping(ns, user_id="user-123", org_id=None)
        assert result[1] == "user-123"

    def test_arbitrary_namespace_is_scoped_under_user(self) -> None:
        """Non-user namespaces get prefixed with the caller's user scope."""
        ns = ["global", "shared-data"]
        result = apply_namespace_scoping(ns, user_id="user-123", org_id=None)
        assert result == ["users", "user-123", "global", "shared-data"]

    def test_single_element_namespace_is_scoped(self) -> None:
        ns = ["configs"]
        result = apply_namespace_scoping(ns, user_id="user-123", org_id=None)
        assert result == ["users", "user-123", "configs"]

    def test_users_prefix_without_id_is_scoped(self) -> None:
        """["users"] alone (no user_id) should be scoped, not passed through."""
        ns = ["users"]
        result = apply_namespace_scoping(ns, user_id="user-123", org_id=None)
        assert result == ["users", "user-123", "users"]

    def test_users_prefix_with_wrong_id_is_scoped(self) -> None:
        ns = ["users", "other-user"]
        result = apply_namespace_scoping(ns, user_id="user-123", org_id=None)
        assert result[1] == "user-123"

    def test_deeply_nested_own_namespace(self) -> None:
        ns = ["users", "user-123", "a", "b", "c"]
        result = apply_namespace_scoping(ns, user_id="user-123", org_id=None)
        assert result == ["users", "user-123", "a", "b", "c"]


class TestOrgNamespaceScoping:
    """Verify that a leading "orgs" element scopes to the caller's organization."""

    def test_fully_qualified_org_namespace_passes_through(self) -> None:
        ns = ["orgs", "org-1", "shared-prompts"]
        result = apply_namespace_scoping(ns, user_id="user-123", org_id="org-1")
        assert result == ["orgs", "org-1", "shared-prompts"]

    def test_org_exact_passes_through(self) -> None:
        ns = ["orgs", "org-1"]
        result = apply_namespace_scoping(ns, user_id="user-123", org_id="org-1")
        assert result == ["orgs", "org-1"]

    def test_not_qualified_org_namespace_is_buried(self) -> None:
        """["orgs", "x"] is not fully qualified, so it gets buried under the caller's org."""
        ns = ["orgs", "shared-prompts"]
        result = apply_namespace_scoping(ns, user_id="user-123", org_id="org-1")
        assert result == ["orgs", "org-1", "orgs", "shared-prompts"]

    def test_other_org_namespace_is_buried(self) -> None:
        """A foreign org id never passes through — it is buried under the caller's org."""
        ns = ["orgs", "victim-org", "secrets"]
        result = apply_namespace_scoping(ns, user_id="user-123", org_id="org-1")
        assert result == ["orgs", "org-1", "orgs", "victim-org", "secrets"]
        assert result[1] == "org-1"

    def test_orgs_prefix_alone_is_buried(self) -> None:
        ns = ["orgs"]
        result = apply_namespace_scoping(ns, user_id="user-123", org_id="org-1")
        assert result == ["orgs", "org-1", "orgs"]

    def test_user_scope_takes_precedence_for_empty_namespace(self) -> None:
        """Empty namespace defaults to user scope even when the user has an org."""
        result = apply_namespace_scoping([], user_id="user-123", org_id="org-1")
        assert result == ["users", "user-123"]

    def test_org_prefix_without_org_id_raises_403(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            apply_namespace_scoping(["orgs", "shared"], user_id="user-123", org_id=None)
        assert exc_info.value.status_code == 403
