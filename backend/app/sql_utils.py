"""Small SQL string helpers shared across modules."""


def escape_like(raw: str) -> str:
    """Escape LIKE wildcards so user input can't widen a search (Step 3).

    Callers MUST pass ``escape="\\\\"`` to the ``like``/``ilike`` call,
    otherwise the backslashes are treated as literal characters and the
    pattern matches nothing.
    """
    return raw.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# Backslash the escape character that callers hand to like()/ilike().
LIKE_ESCAPE = "\\"