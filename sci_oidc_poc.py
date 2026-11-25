#!/usr/bin/env python3
"""Read-only GitHub OIDC -> IAS -> SCIM POC with safe diagnostics."""

import json
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


JWT_CLIENT_AUTH = (
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)
JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"

SAFE_OAUTH_ERRORS = {
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
    "invalid_target",
    "access_denied",
    "login_required",
    "server_error",
    "temporarily_unavailable",
}

MAX_RESPONSE_BYTES = 1024 * 1024


class POCError(Exception):
    def __init__(self, message, *, http_status=None, oauth_error=None):
        super().__init__(message)
        self.http_status = http_status
        self.oauth_error = oauth_error


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Uses standard TLS verification and refuses redirects.
OPENER = build_opener(NoRedirects())


def required(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise POCError(f"Missing environment variable: {name}")
    return value


def check_https(url):
    try:
        parsed = urlparse(url)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname
            and parsed.username is None
            and parsed.password is None
            and not parsed.fragment
            and not any(character.isspace() for character in url)
        )
    except ValueError:
        valid = False

    if not valid:
        raise POCError("Invalid HTTPS endpoint configuration.")


def mask(token):
    # Keep stdout available for the final JSON result.
    if os.environ.get("GITHUB_ACTIONS") == "true":
        escaped = (
            token.replace("%", "%25")
            .replace("\r", "%0D")
            .replace("\n", "%0A")
        )
        print(f"::add-mask::{escaped}", file=sys.stderr)


def read_json(response):
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("Response too large")
    return json.loads(raw)


def request_json(url, *, form=None, bearer=None, label):
    check_https(url)

    headers = {"Accept": "application/json"}
    data = None

    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urlencode(form).encode("utf-8")

    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"

    request = Request(url, data=data, headers=headers)

    try:
        with OPENER.open(request, timeout=30) as response:
            payload = read_json(response)

    except HTTPError as exc:
        status = exc.code
        oauth_error = None

        try:
            body = read_json(exc)
            candidate = (
                body.get("error") if isinstance(body, dict) else None
            )

            # Only emit known OAuth codes. Never print arbitrary error
            # descriptions, response bodies, tokens or identity records.
            if (
                isinstance(candidate, str)
                and candidate in SAFE_OAUTH_ERRORS
            ):
                oauth_error = candidate

        except (ValueError, OSError):
            pass

        finally:
            exc.close()

        suffix = f" ({oauth_error})" if oauth_error else ""
        raise POCError(
            f"{label}: HTTP {status}{suffix}",
            http_status=status,
            oauth_error=oauth_error,
        ) from None

    except (URLError, TimeoutError, OSError):
        raise POCError(f"{label}: network/TLS failure") from None

    except ValueError:
        raise POCError(f"{label}: invalid JSON response") from None

    if not isinstance(payload, dict):
        raise POCError(f"{label}: expected a JSON object")

    return payload


def get_github_jwt(audience):
    request_url = required("ACTIONS_ID_TOKEN_REQUEST_URL")
    request_token = required("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    check_https(request_url)

    parsed = urlparse(request_url)

    # Replace any existing audience and encode the exact requested value.
    query = [
        (key, value)
        for key, value in parse_qsl(parsed.query)
        if key != "audience"
    ]
    query.append(("audience", audience))

    request_url = urlunparse(
        parsed._replace(query=urlencode(query))
    )

    payload = request_json(
        request_url,
        bearer=request_token,
        label="GitHub OIDC issuance",
    )

    assertion = payload.get("value")

    if not isinstance(assertion, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        assertion,
    ):
        raise POCError("GitHub did not return a compact JWT.")

    # This is syntax checking only. IAS verifies signature and claims.
    mask(assertion)
    return assertion


def failure_hint(stage, error):
    if stage == "github_oidc":
        return (
            "Check id-token: write, GitHub OIDC availability "
            "and runner connectivity."
        )

    if stage == "ias_token":
        hints = {
            "invalid_client": (
                "Check the IAS application client ID and its JWT "
                "client-authentication issuer, subject and audience."
            ),
            "invalid_grant": (
                "Check assertion validity, corporate-IdP federation "
                "and helper-user mapping for the selected flow."
            ),
            "invalid_request": (
                "Check the selected flow, required request parameters "
                "and configured SCIM dependency."
            ),
            "unauthorized_client": (
                "Check whether this IAS application is allowed "
                "to use the selected grant."
            ),
            "unsupported_grant_type": (
                "Check whether IAS supports the requested grant."
            ),
            "invalid_target": (
                "Check SCI_OIDC_RESOURCE and the application's "
                "Administration Console SCIM dependency."
            ),
        }
        return hints.get(
            error.oauth_error,
            "IAS rejected the exchange. Check the OAuth error code, "
            "application JWT trust, federation and dependency setup.",
        )

    if stage == "scim":
        return (
            "IAS issued a token, but SCIM did not accept the request. "
