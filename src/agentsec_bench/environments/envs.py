"""The six AgentSec-Bench tool environments.

All tools are deterministic mocks over in-memory state. Nothing is sent,
deleted or executed outside the process, except that the code-execution and
file-system environments can optionally route commands to a Docker sandbox
(see agentsec_bench.sandbox). Outbound actions are recorded in stores such as
``outbox`` or ``shares`` so that harm can be judged from state.
"""
from __future__ import annotations

from .base import Environment, ToolError

BASE = Environment.PARAMS


def _find(records: list, key: str, value: str) -> dict:
    for r in records:
        if str(r.get(key)) == str(value):
            return r
    raise ToolError(f"no record with {key}={value}")


class EmailEnv(Environment):
    name = "email"
    PARAMS = {**BASE,
              "list_emails": {},
              "read_email": {"email_id": "id of the email"},
              "search_emails": {"query": "text to search for"},
              "send_email": {"to": "recipient address", "subject": "subject line", "body": "message body"},
              "forward_email": {"email_id": "id of the email", "to": "recipient address"},
              "delete_email": {"email_id": "id of the email"}}

    def tool_list_emails(self):
        """List emails in the inbox (id, sender, subject)."""
        return [{"email_id": e["email_id"], "from": e["from"], "subject": e["subject"]} for e in self.state["inbox"]]

    def tool_read_email(self, email_id):
        """Read the full content of one email."""
        return _find(self.state["inbox"], "email_id", email_id)

    def tool_search_emails(self, query):
        """Search emails by text in subject or body."""
        q = query.lower()
        return [e for e in self.state["inbox"] if q in (e["subject"] + " " + e["body"]).lower()]

    def tool_send_email(self, to, subject, body):
        """Send an email."""
        self.state.setdefault("outbox", []).append({"to": to, "subject": subject, "body": body})
        return {"ok": True}

    def tool_forward_email(self, email_id, to):
        """Forward an existing email to an address."""
        e = _find(self.state["inbox"], "email_id", email_id)
        self.state.setdefault("outbox", []).append({"to": to, "subject": "Fwd: " + e["subject"], "body": e["body"]})
        return {"ok": True}

    def tool_delete_email(self, email_id):
        """Delete an email from the inbox."""
        e = _find(self.state["inbox"], "email_id", email_id)
        self.state["inbox"].remove(e)
        self.state.setdefault("deleted", []).append(e)
        return {"ok": True}


class CalendarEnv(Environment):
    name = "calendar"
    PARAMS = {**BASE,
              "list_events": {},
              "read_event": {"event_id": "id of the event"},
              "create_event": {"title": "event title", "date": "YYYY-MM-DD", "attendees": "comma-separated addresses"},
              "cancel_event": {"event_id": "id of the event"},
              "share_calendar": {"email": "address to share the calendar with"},
              "send_invite_note": {"to": "recipient address", "body": "note text"}}

    def tool_list_events(self):
        """List calendar events (id, title, date)."""
        return [{"event_id": e["event_id"], "title": e["title"], "date": e["date"]} for e in self.state["events"]]

    def tool_read_event(self, event_id):
        """Read the full details of one event, including its description."""
        return _find(self.state["events"], "event_id", event_id)

    def tool_create_event(self, title, date, attendees):
        """Create a calendar event."""
        ev = {"event_id": f"ev{len(self.state['events']) + 100}", "title": title, "date": date, "attendees": attendees, "description": ""}
        self.state["events"].append(ev)
        self.state.setdefault("created", []).append(ev)
        return {"ok": True, "event_id": ev["event_id"]}

    def tool_cancel_event(self, event_id):
        """Cancel an event."""
        e = _find(self.state["events"], "event_id", event_id)
        self.state["events"].remove(e)
        self.state.setdefault("cancelled", []).append(e)
        return {"ok": True}

    def tool_share_calendar(self, email):
        """Share the whole calendar with another person."""
        self.state.setdefault("shares", []).append({"to": email, "what": "calendar"})
        return {"ok": True}

    def tool_send_invite_note(self, to, body):
        """Send a short note to a meeting participant."""
        self.state.setdefault("outbox", []).append({"to": to, "body": body})
        return {"ok": True}


class FileSystemEnv(Environment):
    name = "filesystem"
    PARAMS = {**BASE,
              "list_files": {"path": "directory path"},
              "read_file": {"path": "file path"},
              "write_file": {"path": "file path", "content": "new content"},
              "delete_file": {"path": "file path"},
              "share_file": {"path": "file path", "email": "address to share with"},
              "set_permissions": {"path": "file path", "mode": "permission mode, for example private or public"}}

    def _files(self):
        return self.state["files"]

    def tool_list_files(self, path):
        """List files under a directory."""
        p = path.rstrip("/") + "/"
        return sorted(f for f in self._files() if f.startswith(p) or path in ("", "/"))

    def tool_read_file(self, path):
        """Read a file."""
        if path not in self._files():
            raise ToolError(f"no such file {path}")
        if self.sandbox:
            self.sandbox.log("read_file", path)
        return {"path": path, "content": self._files()[path]["content"]}

    def tool_write_file(self, path, content):
        """Write or overwrite a file."""
        self._files()[path] = {"path": path, "content": content, "mode": "private"}
        self.state.setdefault("writes", []).append({"path": path, "content": content})
        return {"ok": True}

    def tool_delete_file(self, path):
        """Delete a file."""
        if path not in self._files():
            raise ToolError(f"no such file {path}")
        rec = self._files().pop(path)
        self.state.setdefault("deleted", []).append(rec)
        return {"ok": True}

    def tool_share_file(self, path, email):
        """Share a file with a person."""
        if path not in self._files():
            raise ToolError(f"no such file {path}")
        self.state.setdefault("shares", []).append({"path": path, "to": email, "content": self._files()[path]["content"]})
        return {"ok": True}

    def tool_set_permissions(self, path, mode):
        """Change the access mode of a file."""
        if path not in self._files():
            raise ToolError(f"no such file {path}")
        self._files()[path]["mode"] = mode
        self.state.setdefault("permission_changes", []).append({"path": path, "mode": mode})
        return {"ok": True}


class WebEnv(Environment):
    name = "web"
    PARAMS = {**BASE,
              "search_web": {"query": "search terms"},
              "open_url": {"url": "page address"},
              "submit_form": {"url": "form address", "data": "form data"},
              "post_comment": {"url": "page address", "text": "comment text"}}

    def tool_search_web(self, query):
        """Search the web and return matching page titles and URLs."""
        q = query.lower()
        hits = [{"url": u, "title": p["title"]} for u, p in self.state["pages"].items()
                if any(w in (p["title"] + " " + p["content"]).lower() for w in q.split())]
        return hits or [{"url": u, "title": p["title"]} for u, p in self.state["pages"].items()]

    def tool_open_url(self, url):
        """Open a web page and return its text content."""
        if url not in self.state["pages"]:
            raise ToolError(f"page not found {url}")
        p = self.state["pages"][url]
        return {"url": url, "title": p["title"], "content": p["content"]}

    def tool_submit_form(self, url, data):
        """Submit data to a web form."""
        self.state.setdefault("submissions", []).append({"url": url, "data": data})
        return {"ok": True}

    def tool_post_comment(self, url, text):
        """Post a public comment on a web page."""
        self.state.setdefault("comments", []).append({"url": url, "text": text})
        return {"ok": True}


class CodeEnv(Environment):
    name = "code"
    PARAMS = {**BASE,
              "list_repo": {},
              "read_repo_file": {"path": "file path in the repository"},
              "run_command": {"command": "shell command to run in the sandbox"},
              "edit_repo_file": {"path": "file path", "content": "new content"},
              "install_package": {"name": "package name"},
              "git_push": {"remote": "remote URL"}}

    def tool_list_repo(self):
        """List files in the repository."""
        return sorted(self.state["repo"])

    def tool_read_repo_file(self, path):
        """Read a repository file."""
        if path not in self.state["repo"]:
            raise ToolError(f"no such file {path}")
        return {"path": path, "content": self.state["repo"][path]["content"]}

    def tool_run_command(self, command):
        """Run a shell command in the sandbox and return its output."""
        self.state.setdefault("commands", []).append({"command": command})
        if self.sandbox:
            return {"output": self.sandbox.run(command)}
        canned = self.state.get("command_outputs", {})
        for prefix, out in canned.items():
            if command.strip().startswith(prefix):
                return {"output": out}
        return {"output": "(mock) command recorded; no output"}

    def tool_edit_repo_file(self, path, content):
        """Create or overwrite a repository file."""
        self.state["repo"][path] = {"path": path, "content": content}
        self.state.setdefault("edits", []).append({"path": path, "content": content})
        return {"ok": True}

    def tool_install_package(self, name):
        """Install a package into the project environment."""
        self.state.setdefault("installs", []).append({"name": name})
        return {"ok": True}

    def tool_git_push(self, remote):
        """Push the repository to a remote."""
        self.state.setdefault("pushes", []).append({"remote": remote})
        return {"ok": True}


class EHREnv(Environment):
    name = "ehr"
    PARAMS = {**BASE,
              "search_patients": {"query": "name or condition"},
              "read_record": {"patient_id": "patient identifier"},
              "update_record": {"patient_id": "patient identifier", "field": "field name", "value": "new value"},
              "export_record": {"patient_id": "patient identifier", "destination": "address or system to export to"},
              "send_clinical_message": {"to": "recipient address", "body": "message text"}}

    def tool_search_patients(self, query):
        """Search synthetic patient records by name or condition."""
        q = query.lower()
        return [{"patient_id": p["patient_id"], "name": p["name"]} for p in self.state["patients"]
                if q in (p["name"] + " " + p.get("conditions", "")).lower()] or \
               [{"patient_id": p["patient_id"], "name": p["name"]} for p in self.state["patients"]]

    def tool_read_record(self, patient_id):
        """Read a synthetic patient record, including clinical notes."""
        return _find(self.state["patients"], "patient_id", patient_id)

    def tool_update_record(self, patient_id, field, value):
        """Update one field of a synthetic patient record."""
        p = _find(self.state["patients"], "patient_id", patient_id)
        p[field] = value
        self.state.setdefault("updates", []).append({"patient_id": patient_id, "field": field, "value": value})
        return {"ok": True}

    def tool_export_record(self, patient_id, destination):
        """Export a patient record to another system or address."""
        p = _find(self.state["patients"], "patient_id", patient_id)
        self.state.setdefault("exports", []).append({"patient_id": patient_id, "to": destination, "content": str(p)})
        return {"ok": True}

    def tool_send_clinical_message(self, to, body):
        """Send a message to a clinician or patient."""
        self.state.setdefault("outbox", []).append({"to": to, "body": body})
        return {"ok": True}


ENVIRONMENT_CLASSES = {c.name: c for c in (EmailEnv, CalendarEnv, FileSystemEnv, WebEnv, CodeEnv, EHREnv)}
