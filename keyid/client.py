"""KeyID API client — full-featured agent email SDK."""

from __future__ import annotations

import platform as _platform
import socket
import sys
import time
from datetime import datetime
from typing import Any
from urllib.parse import quote

import httpx

from .crypto import generate_keypair, sign
from . import __version__


class KeyID:
    """KeyID agent client.

    Usage::

        agent = KeyID()
        result = agent.provision()
        print(result["email"])

        inbox = agent.get_inbox()
        agent.send("user@example.com", "Hello", "Body text")

        # Threads
        threads = agent.list_threads()
        thread = agent.get_thread(thread_id)

        # Drafts
        draft_id = agent.create_draft(to="x@y.com", subject="Hi")["draftId"]
        agent.send_draft(draft_id)

        # Webhooks
        wh = agent.create_webhook("https://example.com/hook", events=["message.received"])

        # Lists
        agent.add_to_list("inbound", "block", "spammer@evil.com")

        # Metrics
        metrics = agent.get_metrics(event="message.received", period="day")
    """

    def __init__(
        self,
        *,
        base_url: str = "https://keyid.ai",
        public_key: str | None = None,
        private_key: str | None = None,
        storage_type: str = "memory",
    ):
        self.base_url = base_url.rstrip("/")
        self.storage_type = storage_type
        self._token: str | None = None
        self._token_expires_at: float = 0

        if public_key and private_key:
            self.public_key = public_key
            self._private_key = private_key
        else:
            self.public_key, self._private_key = generate_keypair()

        self._client = httpx.Client(base_url=self.base_url, timeout=30)

    # -- Identity & Auth ------------------------------------------

    def provision(self) -> dict[str, Any]:
        """Register agent and get an email address."""
        meta: dict[str, str] = {
            "sdk": "keyid-py",
            "sdkVersion": __version__,
            "runtime": "python",
            "runtimeVersion": _platform.python_version(),
            "platform": sys.platform,
        }
        try:
            meta["hostname"] = socket.gethostname()
        except Exception:
            pass
        return self._request(
            "POST",
            "/api/provision",
            json={"pubkey": self.public_key, "storageType": self.storage_type, **meta},
        )

    def authenticate(self) -> str:
        """Authenticate via challenge-response. Returns JWT token."""
        data = self._request(
            "POST", "/api/auth/challenge", json={"pubkey": self.public_key}
        )
        nonce = data["nonce"]
        signature = sign(nonce, self._private_key)

        result = self._request(
            "POST",
            "/api/auth/verify",
            json={"pubkey": self.public_key, "nonce": nonce, "signature": signature},
        )

        self._token = result["token"]
        self._token_expires_at = datetime.fromisoformat(
            result["expiresAt"].replace("Z", "+00:00")
        ).timestamp()
        return self._token

    def get_identity(self) -> dict[str, Any]:
        """Get current agent identity info."""
        self._ensure_auth()
        return self._request("GET", "/api/identity", auth=True)

    def get_email(self) -> str:
        """Get current active email address."""
        return self.get_identity()["email"]

    def get_addresses(self) -> list[dict[str, Any]]:
        """Get all email addresses (current and historical)."""
        self._ensure_auth()
        return self._request("GET", "/api/addresses", auth=True)["addresses"]

    # -- Inbox / Messages -----------------------------------------

    def get_inbox(
        self,
        *,
        page: int = 1,
        limit: int = 50,
        direction: str | None = None,
        since: str | None = None,
        labels: list[str] | None = None,
        search: str | None = None,
    ) -> dict[str, Any]:
        """Fetch inbox messages with optional full-text search."""
        self._ensure_auth()
        params: dict[str, Any] = {"page": page, "limit": limit}
        if direction:
            params["direction"] = direction
        if since:
            params["since"] = since
        if labels:
            params["labels"] = ",".join(labels)
        if search:
            params["search"] = search
        return self._request("GET", "/api/inbox", params=params, auth=True)

    def get_message(self, message_id: str) -> dict[str, Any]:
        """Get a single message by ID."""
        self._ensure_auth()
        return self._request("GET", f"/api/inbox/{message_id}", auth=True)

    def update_message(
        self, message_id: str, *, labels: list[str] | None = None, status: str | None = None,
        is_read: bool | None = None, is_starred: bool | None = None,
    ) -> dict[str, Any]:
        """Update message labels, status, read/starred state."""
        self._ensure_auth()
        body: dict[str, Any] = {}
        if labels is not None:
            body["labels"] = labels
        if status is not None:
            body["status"] = status
        if is_read is not None:
            body["isRead"] = is_read
        if is_starred is not None:
            body["isStarred"] = is_starred
        return self._request("PATCH", f"/api/inbox/{message_id}", json=body, auth=True)

    def send(
        self,
        to: str,
        subject: str,
        body: str,
        *,
        html: str | None = None,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        reply_to: str | None = None,
        thread_id: str | None = None,
        labels: list[str] | None = None,
        attachments: list[dict[str, Any]] | None = None,
        display_name: str | None = None,
        scheduled_at: str | None = None,
    ) -> dict[str, Any]:
        """Send an email with optional HTML, CC, BCC, attachments, scheduling."""
        self._ensure_auth()
        payload: dict[str, Any] = {"to": to, "subject": subject, "body": body}
        if html:
            payload["html"] = html
        if cc:
            payload["cc"] = cc
        if bcc:
            payload["bcc"] = bcc
        if reply_to:
            payload["replyTo"] = reply_to
        if thread_id:
            payload["threadId"] = thread_id
        if labels:
            payload["labels"] = labels
        if attachments:
            payload["attachments"] = attachments
        if display_name:
            payload["displayName"] = display_name
        if scheduled_at:
            payload["scheduledAt"] = scheduled_at
        return self._request("POST", "/api/send", json=payload, auth=True)

    def reply(self, message_id: str, body: str, *, html: str | None = None) -> dict[str, Any]:
        """Reply to a message."""
        self._ensure_auth()
        payload: dict[str, Any] = {"body": body}
        if html:
            payload["html"] = html
        return self._request("POST", f"/api/inbox/{message_id}/reply", json=payload, auth=True)

    def reply_all(self, message_id: str, body: str, *, html: str | None = None) -> dict[str, Any]:
        """Reply-all to a message."""
        self._ensure_auth()
        payload: dict[str, Any] = {"body": body}
        if html:
            payload["html"] = html
        return self._request("POST", f"/api/inbox/{message_id}/reply-all", json=payload, auth=True)

    def forward(self, message_id: str, to: str, *, body: str | None = None, html: str | None = None) -> dict[str, Any]:
        """Forward a message to another recipient."""
        self._ensure_auth()
        payload: dict[str, Any] = {"to": to}
        if body:
            payload["body"] = body
        if html:
            payload["html"] = html
        return self._request("POST", f"/api/inbox/{message_id}/forward", json=payload, auth=True)

    # -- Threads --------------------------------------------------

    def list_threads(
        self,
        *,
        page: int = 1,
        limit: int = 50,
        labels: list[str] | None = None,
        before: str | None = None,
        after: str | None = None,
        ascending: bool = False,
    ) -> dict[str, Any]:
        """List conversation threads."""
        self._ensure_auth()
        params: dict[str, Any] = {"page": page, "limit": limit}
        if labels:
            params["labels"] = ",".join(labels)
        if before:
            params["before"] = before
        if after:
            params["after"] = after
        if ascending:
            params["ascending"] = "true"
        return self._request("GET", "/api/threads", params=params, auth=True)

    def get_thread(self, thread_id: str) -> dict[str, Any]:
        """Get a thread with all its messages."""
        self._ensure_auth()
        return self._request("GET", f"/api/threads/{thread_id}", auth=True)

    def delete_thread(self, thread_id: str, *, permanent: bool = False) -> dict[str, Any]:
        """Delete a thread (soft by default, permanent if specified)."""
        self._ensure_auth()
        params = {"permanent": "true"} if permanent else None
        return self._request("DELETE", f"/api/threads/{thread_id}", params=params, auth=True)

    # -- Drafts ---------------------------------------------------

    def list_drafts(self, *, page: int = 1, limit: int = 50) -> dict[str, Any]:
        """List all drafts."""
        self._ensure_auth()
        return self._request("GET", "/api/drafts", params={"page": page, "limit": limit}, auth=True)

    def create_draft(
        self,
        *,
        to: str | None = None,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        reply_to: str | None = None,
        subject: str | None = None,
        body: str | None = None,
        html_body: str | None = None,
        thread_id: str | None = None,
        labels: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a new draft."""
        self._ensure_auth()
        payload: dict[str, Any] = {}
        if to is not None: payload["to"] = to
        if cc is not None: payload["cc"] = cc
        if bcc is not None: payload["bcc"] = bcc
        if reply_to is not None: payload["replyTo"] = reply_to
        if subject is not None: payload["subject"] = subject
        if body is not None: payload["body"] = body
        if html_body is not None: payload["htmlBody"] = html_body
        if thread_id is not None: payload["threadId"] = thread_id
        if labels is not None: payload["labels"] = labels
        return self._request("POST", "/api/drafts", json=payload, auth=True)

    def get_draft(self, draft_id: str) -> dict[str, Any]:
        """Get a draft by ID."""
        self._ensure_auth()
        return self._request("GET", f"/api/drafts/{draft_id}", auth=True)

    def update_draft(self, draft_id: str, **fields: Any) -> dict[str, Any]:
        """Update a draft. Pass any fields: to, cc, bcc, subject, body, htmlBody, labels."""
        self._ensure_auth()
        return self._request("PATCH", f"/api/drafts/{draft_id}", json=fields, auth=True)

    def delete_draft(self, draft_id: str) -> dict[str, Any]:
        """Delete a draft."""
        self._ensure_auth()
        return self._request("DELETE", f"/api/drafts/{draft_id}", auth=True)

    def send_draft(self, draft_id: str) -> dict[str, Any]:
        """Send a draft."""
        self._ensure_auth()
        return self._request("POST", f"/api/drafts/{draft_id}/send", auth=True)

    # -- Webhooks -------------------------------------------------

    def list_webhooks(self) -> dict[str, Any]:
        """List all webhooks."""
        self._ensure_auth()
        return self._request("GET", "/api/webhooks", auth=True)

    def create_webhook(self, url: str, *, events: list[str] | None = None) -> dict[str, Any]:
        """Create a webhook. Returns webhookId and secret."""
        self._ensure_auth()
        payload: dict[str, Any] = {"url": url}
        if events:
            payload["events"] = events
        return self._request("POST", "/api/webhooks", json=payload, auth=True)

    def get_webhook(self, webhook_id: str) -> dict[str, Any]:
        """Get a webhook by ID."""
        self._ensure_auth()
        return self._request("GET", f"/api/webhooks/{webhook_id}", auth=True)

    def update_webhook(
        self, webhook_id: str, *, url: str | None = None, events: list[str] | None = None, active: bool | None = None
    ) -> dict[str, Any]:
        """Update a webhook."""
        self._ensure_auth()
        payload: dict[str, Any] = {}
        if url is not None: payload["url"] = url
        if events is not None: payload["events"] = events
        if active is not None: payload["active"] = active
        return self._request("PATCH", f"/api/webhooks/{webhook_id}", json=payload, auth=True)

    def delete_webhook(self, webhook_id: str) -> dict[str, Any]:
        """Delete a webhook."""
        self._ensure_auth()
        return self._request("DELETE", f"/api/webhooks/{webhook_id}", auth=True)

    # -- Lists (allowlist/blocklist) ------------------------------

    def get_list(
        self, direction: str, type: str, *, page: int = 1, limit: int = 50
    ) -> dict[str, Any]:
        """Get entries from a list. direction: inbound|outbound, type: allow|block."""
        self._ensure_auth()
        return self._request(
            "GET", f"/api/lists/{direction}/{type}",
            params={"page": page, "limit": limit}, auth=True,
        )

    def add_to_list(self, direction: str, type: str, entry: str) -> dict[str, Any]:
        """Add an entry (email or domain) to a list."""
        self._ensure_auth()
        return self._request(
            "POST", f"/api/lists/{direction}/{type}",
            json={"entry": entry}, auth=True,
        )

    def remove_from_list(self, direction: str, type: str, entry: str) -> dict[str, Any]:
        """Remove an entry from a list."""
        self._ensure_auth()
        return self._request(
            "DELETE", f"/api/lists/{direction}/{type}/{quote(entry, safe='')}",
            auth=True,
        )

    # -- Metrics --------------------------------------------------

    def get_metrics(
        self,
        *,
        event: str | None = None,
        period: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> dict[str, Any]:
        """Get metrics. period: hour|day|week|month."""
        self._ensure_auth()
        params: dict[str, Any] = {}
        if event: params["event"] = event
        if period: params["period"] = period
        if since: params["since"] = since
        if until: params["until"] = until
        return self._request("GET", "/api/metrics", params=params, auth=True)

    # -- Settings -------------------------------------------------

    def get_signature(self) -> dict[str, Any]:
        """Get email signature setting."""
        self._ensure_auth()
        return self._request("GET", "/api/settings/signature", auth=True)

    def set_signature(self, signature: str | None) -> dict[str, Any]:
        """Set email signature."""
        self._ensure_auth()
        return self._request("PUT", "/api/settings/signature", json={"signature": signature}, auth=True)

    def get_forwarding(self) -> dict[str, Any]:
        """Get auto-forwarding setting."""
        self._ensure_auth()
        return self._request("GET", "/api/settings/forwarding", auth=True)

    def set_forwarding(self, forwarding_address: str | None) -> dict[str, Any]:
        """Set auto-forwarding address."""
        self._ensure_auth()
        return self._request("PUT", "/api/settings/forwarding", json={"forwardingAddress": forwarding_address}, auth=True)

    def get_auto_reply(self) -> dict[str, Any]:
        """Get auto-reply / vacation responder settings."""
        self._ensure_auth()
        return self._request("GET", "/api/settings/auto-reply", auth=True)

    def set_auto_reply(
        self,
        *,
        enabled: bool | None = None,
        subject: str | None = None,
        body: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> dict[str, Any]:
        """Configure auto-reply / vacation responder."""
        self._ensure_auth()
        payload: dict[str, Any] = {}
        if enabled is not None: payload["enabled"] = enabled
        if subject is not None: payload["subject"] = subject
        if body is not None: payload["body"] = body
        if start_date is not None: payload["startDate"] = start_date
        if end_date is not None: payload["endDate"] = end_date
        return self._request("PUT", "/api/settings/auto-reply", json=payload, auth=True)

    # -- Unread Count ---------------------------------------------

    def get_unread_count(self) -> dict[str, Any]:
        """Get count of unread inbound messages."""
        self._ensure_auth()
        return self._request("GET", "/api/inbox/unread-count", auth=True)

    # -- Contacts -------------------------------------------------

    def list_contacts(self) -> dict[str, Any]:
        """List all contacts."""
        self._ensure_auth()
        return self._request("GET", "/api/contacts", auth=True)

    def create_contact(self, email: str, *, name: str | None = None, notes: str | None = None) -> dict[str, Any]:
        """Create or upsert a contact."""
        self._ensure_auth()
        payload: dict[str, Any] = {"email": email}
        if name: payload["name"] = name
        if notes: payload["notes"] = notes
        return self._request("POST", "/api/contacts", json=payload, auth=True)

    def get_contact(self, contact_id: str) -> dict[str, Any]:
        """Get a contact by ID."""
        self._ensure_auth()
        return self._request("GET", f"/api/contacts/{contact_id}", auth=True)

    def update_contact(self, contact_id: str, **fields: Any) -> dict[str, Any]:
        """Update a contact. Fields: name, email, notes."""
        self._ensure_auth()
        return self._request("PATCH", f"/api/contacts/{contact_id}", json=fields, auth=True)

    def delete_contact(self, contact_id: str) -> dict[str, Any]:
        """Delete a contact."""
        self._ensure_auth()
        return self._request("DELETE", f"/api/contacts/{contact_id}", auth=True)

    # -- Webhook Deliveries ---------------------------------------

    def get_webhook_deliveries(self, *, page: int = 1, limit: int = 50) -> dict[str, Any]:
        """Get paginated webhook delivery logs."""
        self._ensure_auth()
        return self._request("GET", "/api/webhooks/deliveries", params={"page": page, "limit": limit}, auth=True)

    # -- Internals ------------------------------------------------

    def _ensure_auth(self) -> None:
        if not self._token or time.time() >= self._token_expires_at - 60:
            self.authenticate()

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict | None = None,
        params: dict | None = None,
        auth: bool = False,
    ) -> dict[str, Any]:
        headers: dict[str, str] = {}
        if auth and self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        resp = self._client.request(
            method, path, json=json, params=params, headers=headers
        )

        if resp.status_code >= 400:
            data = resp.json()
            raise KeyIDError(data.get("error", f"HTTP {resp.status_code}"), resp.status_code)

        return resp.json()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> KeyID:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class KeyIDError(Exception):
    def __init__(self, message: str, status: int):
        super().__init__(message)
        self.status = status
