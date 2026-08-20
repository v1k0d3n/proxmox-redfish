"""Redaction helpers for debug logging.

The request logs are genuinely useful when debugging an Ironic or ACM
integration, but a verbatim dump of headers and bodies puts Basic auth
credentials and session passwords into the system journal. These helpers
keep the diagnostic value -- path, method, which headers were sent, the
shape of the payload -- while removing the parts worth stealing.
"""

from typing import Any, Dict, Iterable, Tuple

REDACTED = "<redacted>"

# Headers whose value is, or directly yields, a credential.
SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "x-auth-token",
        "cookie",
        "set-cookie",
    }
)

# Payload keys that carry secrets. Matched case-insensitively.
SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "pass",
        "secret",
        "token",
        "apikey",
        "api_key",
        "authorization",
        "credential",
        "credentials",
    }
)


def redact_header_value(name: str, value: str) -> str:
    """Mask a header value, keeping the auth scheme where there is one.

    'Basic dXNlcjpwdw==' becomes 'Basic <redacted>', so the log still
    shows which authentication method the client attempted.
    """
    if name.lower() not in SENSITIVE_HEADERS:
        return value
    scheme, separator, _ = value.partition(" ")
    if separator and scheme.isalpha():
        return f"{scheme} {REDACTED}"
    return REDACTED


def redact_headers(headers: Iterable[Tuple[str, str]]) -> str:
    """Render headers for logging with sensitive values masked."""
    return "\n".join(f"{name}: {redact_header_value(name, value)}" for name, value in headers)


def redact_payload(payload: Any) -> Any:
    """Copy a decoded payload with secret-bearing values masked.

    Structure is preserved so the log still shows which fields were sent.
    Non-dict payloads are returned unchanged; a bare string body carries
    no key to match on, and the callers only ever log parsed JSON or an
    already-safe placeholder.
    """
    if isinstance(payload, dict):
        redacted: Dict[Any, Any] = {}
        for key, value in payload.items():
            if isinstance(key, str) and key.lower() in SENSITIVE_KEYS:
                redacted[key] = REDACTED
            else:
                redacted[key] = redact_payload(value)
        return redacted
    if isinstance(payload, list):
        return [redact_payload(item) for item in payload]
    return payload


# The session-creation response body carries the freshly minted token in
# both "Id" and "@odata.id". Those keys are ordinary identifiers on every
# other endpoint, so they are only masked for this one path.
SESSION_PATH = "/redfish/v1/SessionService/Sessions"


def redact_response(path: str, response: Any) -> Any:
    """Copy a response body, masking a session token when one is present.

    Only the SessionService path is treated specially. Redacting "Id"
    everywhere would strip the VM identifiers that make these logs worth
    reading.
    """
    if not isinstance(response, dict):
        return response
    if not path.rstrip("/").startswith(SESSION_PATH):
        return response

    redacted = dict(response)
    if "Id" in redacted:
        redacted["Id"] = REDACTED
    if "@odata.id" in redacted and isinstance(redacted["@odata.id"], str):
        redacted["@odata.id"] = f"{SESSION_PATH}/{REDACTED}"
    return redacted
