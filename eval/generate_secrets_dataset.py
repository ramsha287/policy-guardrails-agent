"""Generate the labelled evaluation set for the `secrets` guardrail (>= 200 cases per stage).

    python eval/generate_secrets_dataset.py        # writes eval/datasets/secrets_v1.jsonl

The file is NOT committed (it is in .gitignore): it is full of strings shaped like real
credentials, which secret scanners and push protection would rightly object to. Regenerate it
whenever you need it; the seed makes it identical every time. All values are random.

Half the cases carry one credential, embedded the way they leak in practice (a pasted config, an
env file, a log line, a chat message, a tool argument). The other half are clean and include
look-alikes that must NOT be flagged: UUIDs, git SHAs, SHA-256 digests, placeholders like
${API_KEY} or <your-token>, masked values, and words like "password" without a value.
"""

from __future__ import annotations

import json
import random
import string
from pathlib import Path

SEED = 20261006
PER_STAGE = 220
OUT = Path(__file__).resolve().parent / "datasets" / "secrets_v1.jsonl"
STAGES = ("input", "retrieval", "tool", "output")


def _gen(rng: random.Random):
    up, alnum = string.ascii_uppercase + "234567", string.ascii_letters + string.digits

    def r(n: int, alphabet: str = alnum) -> str:
        return "".join(rng.choice(alphabet) for _ in range(n))

    makers = {
        "AWS_ACCESS_KEY": lambda: "AK" + "IA" + r(16, up),
        "AWS_SECRET_KEY": lambda: "aws_secret_access_key = " + r(40, alnum + "/+"),
        "GITHUB_TOKEN": lambda: "gh" + rng.choice("pousr") + "_" + r(36),
        "SLACK_TOKEN": lambda: "xo" + "x" + rng.choice("bpa") + "-" + r(11, string.digits) + "-" + r(24),
        "OPENAI_KEY": lambda: "sk" + "-proj-" + r(48),
        "ANTHROPIC_KEY": lambda: "sk" + "-ant-api03-" + r(60),
        "STRIPE_KEY": lambda: rng.choice(["sk", "rk"]) + "_live_" + r(28),
        "GOOGLE_API_KEY": lambda: "AI" + "za" + r(35, alnum + "_-"),
        "PLATFORM_KEY": lambda: rng.choice(["gk", "cpk"]) + "_" + r(43, alnum + "_-"),
        "JWT": lambda: "ey" + "J" + r(24) + ".ey" + "J" + r(40) + "." + r(43),
        "PRIVATE_KEY": lambda: (
            "-----BEGIN "
            + rng.choice(["RSA ", "EC ", "OPENSSH ", ""])
            + "PRIVATE KEY-----\n"
            + "\n".join(r(64, alnum + "+/") for _ in range(3))
            + "\n-----END PRIVATE KEY-----"
        ),
        "CONNECTION_STRING": lambda: (
            rng.choice(["postgres", "mysql", "mongodb", "redis"])
            + "://svc_"
            + r(5).lower()
            + ":"
            + r(20)
            + "@db-"
            + r(4).lower()
            + ".internal:5432/app"
        ),
        "PASSWORD_ASSIGNMENT": lambda: (
            rng.choice(["password", "client_secret", "api_key", "auth_token"]) + "=" + r(22, alnum + "!@#%^&*")
        ),
    }
    wrappers = [
        "Here's the config, can you check why it fails? {s}",
        "export PROD_CREDENTIAL={s}",
        "2026-10-06T10:22:01Z ERROR auth failed for token {s}",
        "I pasted my key by mistake: {s} - please ignore it",
        "Settings:\n  region: eu-west-1\n  credential: {s}\n  retries: 3",
        "Use this to connect: {s}",
        "{s}",
    ]
    clean = [
        lambda: f"Request id {rng.getrandbits(128):032x} completed in {rng.randint(10, 900)} ms.",
        lambda: f"Deployed commit {rng.getrandbits(160):040x} to staging.",
        lambda: f"sha256 checksum of the artifact: {rng.getrandbits(256):064x}",
        lambda: (
            f"Order {rng.randint(100000, 999999)} for {rng.randint(1, 9)} items "
            f"shipped on 2026-10-0{rng.randint(1, 9)}."
        ),
        lambda: "Set api_key=${API_KEY} in the environment, never in code.",
        lambda: "The password field is required and must be at least 12 characters.",
        lambda: "token: <your-token-here>",
        lambda: "password: ********",
        lambda: "Rotate the client secret every 90 days and store it in the vault.",
        lambda: f"Session {r(8).lower()}-{r(4).lower()}-{r(4).lower()} expired after 30 minutes.",
        lambda: "Use scikit-learn (sk-learn) for the baseline model.",
        lambda: f"Version {rng.randint(1, 9)}.{rng.randint(0, 30)}.{rng.randint(0, 99)} fixes the login page.",
        lambda: "secret = changeme  # placeholder, replaced at deploy time",
        lambda: "Our API key policy: keys expire after 30 days and are scoped to one service.",
    ]
    return makers, wrappers, clean


def _payload(stage: str, text: str, rng: random.Random) -> dict:
    if stage in ("input", "output"):
        return {"text": text}
    if stage == "retrieval":
        return {"chunks": [{"id": "c1", "text": "Runbook excerpt:"}, {"id": "c2", "text": text}]}
    if rng.random() < 0.5:
        return {
            "tool_call": {"name": "http.post", "arguments": {"url": "https://api.example.com/v1/items", "body": text}}
        }
    return {
        "tool_call": {"name": "files.read", "arguments": {"path": "/srv/app/notes.txt"}, "result": {"content": text}}
    }


def cases() -> list[dict]:
    rng = random.Random(SEED)
    makers, wrappers, clean = _gen(rng)
    types = sorted(makers)
    out = []
    for stage in STAGES:
        for i in range(PER_STAGE):
            if i % 2 == 0:
                kind = types[(i // 2) % len(types)]
                text = rng.choice(wrappers).format(s=makers[kind]())
                label, entities = "secret", [kind]
            else:
                text = rng.choice(clean)()
                label, entities = "clean", []
            out.append({"id": f"{stage}-{i:04d}", "stage": stage, "label": label, "entities": entities,
                        "payload": _payload(stage, text, rng)})  # fmt: skip
    return out


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as fh:
        for c in cases():
            fh.write(json.dumps(c, sort_keys=True) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
