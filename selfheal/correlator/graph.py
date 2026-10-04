"""Declared dependency relationships; discovery never authorizes actions."""

from selfheal.config import Service


class DependencyGraph:
    """Edges point from a consumer toward its dependencies."""

    def __init__(self, services: list[Service]) -> None:
        """Build a graph from validated inventory."""
        self.edges = {s.name: set(s.depends_on) for s in services}

    def dependencies(self, service: str) -> set[str]:
        """Return transitive dependencies, tolerating defensive cycle checks."""
        found: set[str] = set()
        pending = list(self.edges.get(service, set()))
        while pending:
            node = pending.pop()
            if node not in found:
                found.add(node)
                pending.extend(self.edges.get(node, set()))
        return found

    def related(self, left: str, right: str) -> bool:
        """Relate only equal services or a dependency path, not unrelated peers."""
        return left == right or left in self.dependencies(right) or right in self.dependencies(left)

    def roots(self, affected: set[str]) -> list[str]:
        """Prefer affected dependencies over their affected consumers."""
        return sorted(s for s in affected if not (self.dependencies(s) & affected))
