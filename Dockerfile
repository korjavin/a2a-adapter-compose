# Runtime image: a2a-adapter serving Claude Code or Codex CLI (A2A_HARNESS) on :9000.
FROM node:22-bookworm-slim AS node

FROM python:3.12-slim-bookworm

ARG A2A_ADAPTER_VERSION=0.2.13
ARG CLAUDE_CODE_VERSION=2.1.300
ARG CODEX_VERSION=0.162.1

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*

# Node LTS from the official image (same Debian release, so glibc matches).
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && npm install -g --no-fund --no-audit \
      @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} @openai/codex@${CODEX_VERSION} \
 && npm cache clean --force

COPY constraints.txt /app/constraints.txt
RUN pip install --no-cache-dir --root-user-action=ignore \
      -c /app/constraints.txt a2a-adapter==${A2A_ADAPTER_VERSION}

# Non-root: claude refuses --dangerously-skip-permissions as root.
# ponytail: home and workspace are 1777 so a `user: PUID:PGID` override (any uid)
# can still write HOME; a named volume on /home/agent inherits this on first use.
RUN groupadd -g 1000 agent \
 && useradd -u 1000 -g 1000 -d /home/agent -M -s /usr/sbin/nologin agent \
 && mkdir -p /home/agent /workspace \
 && chown agent:agent /home/agent /workspace \
 && chmod 1777 /home/agent /workspace

COPY entrypoint.py /app/entrypoint.py

ENV HOME=/home/agent \
    PYTHONUNBUFFERED=1 \
    A2A_PORT=9000
USER agent
WORKDIR /workspace
EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/.well-known/agent-card.json' % os.environ['A2A_PORT'], timeout=4)"

ENTRYPOINT ["tini", "--", "python", "/app/entrypoint.py"]
