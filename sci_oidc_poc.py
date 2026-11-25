#!/usr/bin/env python3
"""Read-only GitHub OIDC -> IAS -> SCIM proof of concept."""

import json
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)

JWT_CLIENT_AUTH = (
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)
JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class POCError(Exception):
    pass


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Standard TLS verification remains enabled. Redirects are refused.
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
            and not any(c.isspace() for c in url)
        )
    except ValueError:
        valid = False

    if not valid:
        raise POCError("Invalid HTTPS endpoint configuration.")


def mask(token):
    if os.environ.get("GITHUB_ACTIONS") == "true":
        escaped = (
            token.replace("%", "%25")
            .replace("\r", "%0D")
            .replace("\n", "%0A")
        )
        print(f"::add-mask::{escaped}", file=sys.stderr)


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
            payload = json.load(response)
    except HTTPError as exc:
        # Do not print response bodies: they could echo tokens or user data.
        status = exc.code
        exc.close()
        raise POCError(f"{label}: HTTP {status}") from None
    except (URLError, TimeoutError, OSError):
        raise POCError(f"{label}: network/TLS failure") from None
    except ValueError:
        raise POCError(f"{label}: invalid JSON response") from None

    if not isinstance(payload, dict):
        raise POCError(f"{label}: expected a JSON object")

    return payload


def github_jwt(audience):
    request_url = required("ACTIONS_ID_TOKEN_REQUEST_URL")
    request_token = required("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    check_https(request_url)

    parsed = urlparse(request_url)
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
    token = payload.get("value")

    if not isinstance(token, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        token,
    ):
        raise POCError("GitHub did not return a compact JWT.")

    mask(token)
    return token


def main():
    stage = "configuration"
    token_acquired = False

    try:
        tenant = required("SCI_TENANT_URL").rstrip("/")
        check_https(tenant)
        if urlparse(tenant).query:
            raise POCError("SCI_TENANT_URL must not contain a query.")

        client_id = required("SCI_CLIENT_ID")
        audience = required("SCI_OIDC_AUDIENCE")
        grant = os.environ.get(
            "SCI_OIDC_GRANT_TYPE", "client_credentials"
        ).strip()

        if grant not in ("client_credentials", "jwt_bearer"):
            raise POCError("Unsupported SCI_OIDC_GRANT_TYPE.")

        resource = None
        if grant == "jwt_bearer":
            resource = required("SCI_OIDC_RESOURCE")

        stage = "github_oidc"
        assertion = github_jwt(audience)

        form = {
            "client_id": client_id,
            "grant_type": "client_credentials",
            "client_assertion_type": JWT_CLIENT_AUTH,
            "client_assertion": assertion,
        }

        if grant == "jwt_bearer":
            # Experimental: the same GitHub JWT authenticates the client
            # and represents the federated IAS helper user.
            form.update({
                "grant_type": JWT_BEARER_GRANT,
                "assertion": assertion,
                "resource": resource,
            })

        stage = "ias_token"
        payload = request_json(
            f"{tenant}/oauth2/token",
            form=form,
            label="IAS token exchange",
        )

        access_token = payload.get("access_token")
        if (
            not isinstance(access_token, str)
            or not access_token
            or any(c.isspace() for c in access_token)
        ):
            raise POCError("IAS did not return a valid access_token.")

        mask(access_token)
        token_acquired = True

        stage = "scim"
        result = request_json(
            f"{tenant}/scim/Users/?count=1&startIndex=1",
            bearer=access_token,
            label="SCIM read-only probe",
        )

        resources = result.get("Resources")
        if not isinstance(resources, list):
            raise POCError("SCIM did not return a Resources list.")

        # Never print the token or returned identity records.
        print(json.dumps({
            "ok": True,
            "grant_type": grant,
            "token_acquired": True,
            "scim_access": True,
            "returned_resources": len(resources),
        }))
        return 0

    except POCError as exc:
        print(json.dumps({
            "ok": False,
            "stage": stage,
            "token_acquired": token_acquired,
            "scim_access": False,
            "error": str(exc),
        }))
        return 1

    except Exception:
        # Avoid tracebacks containing request/token details.
        print(json.dumps({
            "ok": False,
            "stage": stage,
            "token_acquired": token_acquired,
            "scim_access": False,
            "error": "Unexpected POC failure.",
        }))
        return 1


if __name__ == "__main__":
    sys.exit(main())
