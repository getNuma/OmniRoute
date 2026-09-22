# ── Common base with runtime deps ──────────────────────────────────────────
FROM node:26-trixie-slim AS base
WORKDIR /app

# `apt-get upgrade` pulls the security-patched versions of the Debian (trixie)
# base-image packages at build time — clears the subset of container-scan CVEs
# (perl / util-linux / systemd / ncurses / zlib / tar / sqlite / shadow / pam …)
# that already have a fix published in trixie. CVEs without an upstream fix yet
# (local-only TOCTOU, etc.) remain until the distro patches them and the image
# is rebuilt; none are reachable from the proxy's request surface at runtime.
RUN apt-get update \
  && apt-get upgrade -y \
  && apt-get install -y --no-install-recommends libsecret-1-0 ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# npm's *bundled* node_modules (brace-expansion, ip-address, tar, undici) are
# npm's own internals — not application dependencies (the app resolves its own,
# already-fixed copies) — but the container scanner reads them off
# /usr/local/lib/node_modules/npm/node_modules and reports 9 HIGH/MEDIUM CVEs.
#
# Refreshing npm does NOT fix them. Measured on npm@12.0.2 (2026-08-12, latest):
#   brace-expansion 5.0.7  (needs >= 5.0.9)   CVE-2026-69152, CVE-2026-14257
#   ip-address      10.2.0 (needs >= 10.3.1)  CVE-2026-69192/-69198/-54272
#   tar             7.5.19 (needs >= 7.5.21)  GHSA-r292-9mhp-454m
#   undici          6.27.0 (needs >= 6.28.0)  CVE-2026-16729/-16728/-15157
# No published npm release carries patched copies, so `npm install -g npm@latest`
# alone was pure build time for zero CVEs — it is kept only to land on a known,
# current npm tree, and the patched copies are overlaid on top below.
#
# Deleting npm from the runner stages is NOT an option: the application shells
# out to npm at runtime (src/lib/services/installers/utils.ts::runNpm for the
# embedded services, src/lib/system/{autoUpdate,globalPackagePath}.ts,
# src/app/api/system/version). The previous version of this comment claimed the
# opposite; it was wrong.
#
# The overlay is semver-compatible with the ranges npm's own tree declares
# (minimatch → brace-expansion ^5.0.5, socks → ip-address ^10.1.1, node-gyp →
# tar ^7.5.4 and undici ^6.25.0 — hence undici stays on the 6.x line, NOT 8.x).
# --install-strategy=nested makes each replacement self-contained, so it cannot
# perturb the versions the rest of npm's flat tree resolves.
RUN set -eux; \
  npm install -g npm@latest; \
  npm install --prefix /tmp/npm-cve-patch --no-audit --no-fund --ignore-scripts \
    --install-strategy=nested \
    brace-expansion@5.0.9 ip-address@10.5.0 tar@7.5.22 undici@6.28.0; \
  for pkg in brace-expansion ip-address tar undici; do \
    test -d "/usr/local/lib/node_modules/npm/node_modules/$pkg"; \
    rm -rf "/usr/local/lib/node_modules/npm/node_modules/$pkg"; \
    cp -R "/tmp/npm-cve-patch/node_modules/$pkg" \
      "/usr/local/lib/node_modules/npm/node_modules/$pkg"; \
  done; \
  rm -rf /tmp/npm-cve-patch; \
  node -e "for (const p of ['brace-expansion','ip-address','tar','undici']) console.log(p, require('/usr/local/lib/node_modules/npm/node_modules/'+p+'/package.json').version);"; \
  npm --version; \
  npm cache clean --force

# ── Builder ────────────────────────────────────────────────────────────────
FROM base AS builder

# No telemetry, anywhere. Disable Next.js's anonymous build-time telemetry
# (it otherwise pings Vercel during `next build`). Set on the builder stage so
# every image build is silent; the runtime never builds, so this covers the
# only phase Next telemetry can fire.
ENV NEXT_TELEMETRY_DISABLED=1

# Build tools for native module compilation
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

COPY package*.json ./

# Workspace package manifests MUST be present before `npm ci` so npm materializes
# the workspace and installs its *workspace-only* deps.
COPY open-sse/package.json ./open-sse/package.json
COPY scripts/build/postinstall.mjs ./scripts/build/postinstall.mjs
COPY scripts/build/postinstallSupport.mjs ./scripts/build/postinstallSupport.mjs
COPY scripts/build/native-binary-compat.mjs ./scripts/build/native-binary-compat.mjs

ENV NPM_CONFIG_LEGACY_PEER_DEPS=true

RUN test -f package-lock.json \
  || (echo "package-lock.json is required for reproducible Docker builds" >&2 && exit 1)

RUN npm ci --include=optional --no-audit --no-fund --legacy-peer-deps --ignore-scripts \
  && (cd node_modules/better-sqlite3 \
      && node /usr/local/lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js rebuild --force_build=1) \
  && test -f node_modules/better-sqlite3/build/Release/better_sqlite3.node \
  && node -e "require('better-sqlite3')(':memory:').close()" \
  && node -e "const wreq=require('wreq-js'); if(typeof wreq.createTransport!=='function') process.exit(1)"

# Build configuration
ARG OMNIROUTE_USE_TURBOPACK=0
ENV OMNIROUTE_USE_TURBOPACK="${OMNIROUTE_USE_TURBOPACK}"

ARG OMNIROUTE_BASE_PATH=""
ENV OMNIROUTE_BASE_PATH=$OMNIROUTE_BASE_PATH

ARG DASHBOARD_ALLOW_EMBED=""
ENV DASHBOARD_ALLOW_EMBED=$DASHBOARD_ALLOW_EMBED

ENV OMNIROUTE_MITM_STUB=1

ARG OMNIROUTE_BUILD_MEMORY_MB=6144
ENV NODE_OPTIONS="--max-old-space-size=${OMNIROUTE_BUILD_MEMORY_MB}"

ARG OMNIROUTE_BUILD_WORKERS=2
ENV CIRCLE_NODE_TOTAL=${OMNIROUTE_BUILD_WORKERS}

COPY . ./

RUN mkdir -p /app/data \
  && npm run build \
  && node --input-type=module -e "import { createRequire } from 'node:module'; import { pathToFileURL } from 'node:url'; const standaloneRoot = '/app/.build/next/standalone/node_modules/'; const require = createRequire('/app/.build/next/standalone/package.json'); for (const pkg of ['@atjsh/llmlingua-2', '@huggingface/transformers', 'js-tiktoken']) { const resolved = require.resolve(pkg); if (!resolved.startsWith(standaloneRoot)) throw new Error(pkg + ' resolved outside standalone: ' + resolved); await import(pathToFileURL(resolved).href); } const onnxRuntime = require.resolve('onnxruntime-node'); if (!onnxRuntime.startsWith(standaloneRoot)) throw new Error('onnxruntime-node resolved outside standalone: ' + onnxRuntime); await import(pathToFileURL(onnxRuntime).href);"

# ── Runner base ────────────────────────────────────────────────────────────
FROM base AS runner-base

LABEL org.opencontainers.image.title="omniroute" \
  org.opencontainers.image.description="Unified AI proxy — route any LLM through one endpoint" \
  org.opencontainers.image.url="https://omniroute.online" \
  org.opencontainers.image.source="https://github.com/diegosouzapw/OmniRoute" \
  org.opencontainers.image.licenses="MIT"

ENV NODE_ENV=production
ENV PORT=20128
ENV HOSTNAME=0.0.0.0

ENV OMNIROUTE_MEMORY_MB=1024
ENV NODE_OPTIONS="--max-old-space-size=${OMNIROUTE_MEMORY_MB}"

ENV DATA_DIR=/app/data
RUN mkdir -p /app/data && chown node:node /app /app/data

ENV REQUIRE_API_KEY=true

COPY --chown=node:node --from=builder /app/.build/next/standalone ./

COPY --chown=node:node --from=builder /app/node_modules/better-sqlite3 ./node_modules/better-sqlite3

RUN test -f /app/node_modules/better-sqlite3/build/Release/better_sqlite3.node

ENV OMNIROUTE_MIGRATIONS_DIR=/app/migrations

COPY --chown=node:node --from=builder /app/scripts/dev/healthcheck.mjs ./healthcheck.mjs

EXPOSE 20128

USER node

COPY --chmod=755 scripts/check-permissions.sh /app/check-permissions.sh

ENTRYPOINT ["/app/check-permissions.sh"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["node", "healthcheck.mjs"]

CMD ["node", "dev/run-standalone.mjs"]

# ── Runner Web ─────────────────────────────────────────────────────────────
FROM runner-base AS runner-web

USER root

COPY --from=builder /app/node_modules/playwright-core ./node_modules/playwright-core
COPY --from=builder /app/node_modules/playwright ./node_modules/playwright

ENV PLAYWRIGHT_BROWSERS_PATH=/home/node/.cache/ms-playwright

RUN apt-get update \
  && node node_modules/playwright/cli.js install chromium --with-deps \
  && chown -R node:node /home/node/.cache \
  && rm -rf /var/lib/apt/lists/*

USER node

# ── Runner CLI ─────────────────────────────────────────────────────────────
FROM runner-base AS runner-cli

USER root

COPY --from=builder /app/node_modules/playwright-core ./node_modules/playwright-core
COPY --from=builder /app/node_modules/playwright ./node_modules/playwright

RUN apt-get update \
  && apt-get install -y --no-install-recommends git ca-certificates docker.io docker-compose \
  && rm -rf /var/lib/apt/lists/* \
  && git config --system url."https://github.com/".insteadOf "ssh://git@github.com/"

RUN npm install -g --no-audit --no-fund \
    @openai/codex@0.153.4 \
    @anthropic-ai/claude-code@2.1.260 \
    droid@0.212.0 \
    openclaw@2026.9.1

USER node