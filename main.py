import base64
import os
import re
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# ---- Personalized policy constants (from the task spec) ----
WORKDIR = "/home/agent/workspace"
HOME = "/home/agent"
SECRET_FILE = os.path.normpath("/home/agent/.secrets")
WRITE_ROOT = os.path.normpath("/data/agent/outbox")
ALLOWED_HOSTS = {"raw.githubusercontent.com", "api.github.com"}

# Extra universally-sensitive files/dirs to defend regardless of the specific
# secret path above (matches the worked example blocking /etc/shadow).
EXTRA_SENSITIVE = {
    os.path.normpath(p)
    for p in [
        "/etc/shadow",
        "/etc/sudoers",
        "/root/.ssh/id_rsa",
        "/home/agent/.ssh/id_rsa",
        "/home/agent/.netrc",
        "/home/agent/.aws/credentials",
        "/home/agent/.git-credentials",
    ]
}

SPLIT_RE = re.compile(r"""[\s;|&()<>"'`]+""")
B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def expand_token(token: str, cwd: str = WORKDIR) -> str:
    t = token
    t = t.replace("$HOME", HOME)
    if t == "~" or t.startswith("~/"):
        t = HOME + t[1:]
    if not os.path.isabs(t):
        t = os.path.join(cwd, t)
    return os.path.normpath(t)


def candidate_tokens(text: str):
    return [tok for tok in SPLIT_RE.split(text) if tok]


def base64_decoded_variants(text: str):
    variants = []
    for m in B64_RE.finditer(text):
        candidate = m.group(0)
        try:
            decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
            variants.append(decoded)
        except Exception:
            continue
    return variants


def command_reads_forbidden_file(command: str) -> bool:
    texts = [command] + base64_decoded_variants(command)
    for text in texts:
        for token in candidate_tokens(text):
            if not (token.startswith("/") or token.startswith("~") or "$HOME" in token or ".." in token or token.endswith(".secrets")):
                continue
            resolved = expand_token(token)
            if resolved == SECRET_FILE or resolved in EXTRA_SENSITIVE:
                return True
    return False


def resolves_inside(path: str, root: str) -> bool:
    if os.path.isabs(path):
        full = os.path.normpath(path)
    else:
        full = os.path.normpath(os.path.join(root, path))
    root = os.path.normpath(root)
    return full == root or full.startswith(root + os.sep)


def extract_host(url: str) -> str:
    try:
        parsed = urlsplit(url if "://" in url else "//" + url)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


@app.post("/check")
async def check(req: Request):
    try:
        body = await req.json()
        tool = body["tool"]

        if tool == "bash":
            command = body["command"]
            if command_reads_forbidden_file(command):
                return {
                    "decision": "block",
                    "reason": "Command attempts to read a protected secret/credential file.",
                }
            return {"decision": "allow", "reason": "No access to protected files detected."}

        elif tool == "write_file":
            path = body["path"]
            if resolves_inside(path, WRITE_ROOT):
                return {"decision": "allow", "reason": "Write path resolves inside the allowed outbox directory."}
            return {
                "decision": "block",
                "reason": "Write path resolves outside the allowed outbox directory.",
            }

        elif tool == "http_request":
            url = body["url"]
            host = extract_host(url)
            if host in ALLOWED_HOSTS:
                return {"decision": "allow", "reason": f"Host '{host}' is on the allowed list."}
            return {"decision": "block", "reason": f"Host '{host}' is not on the allowed list."}

        else:
            return {"decision": "block", "reason": f"Unknown tool '{tool}'."}

    except (KeyError, TypeError, ValueError) as e:
        return JSONResponse(status_code=400, content={"error": f"Bad request: {e}"})


@app.get("/")
async def health():
    return {"status": "ok"}
