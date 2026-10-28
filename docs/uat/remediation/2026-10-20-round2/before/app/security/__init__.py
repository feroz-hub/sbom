"""Cross-cutting security primitives.

Currently houses :mod:`app.security.secrets` (AES-GCM envelope encryption
for at-rest credentials). Future additions: signed-URL helpers, JWT
introspection, etc.
"""

from .secrets import SecretCipher, generate_master_key

__all__ = ["SecretCipher", "generate_master_key"]
