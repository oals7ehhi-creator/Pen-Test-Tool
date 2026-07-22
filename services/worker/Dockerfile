# syntax=docker/dockerfile:1
# @pentest/worker image (prod-only runtime via `pnpm deploy`, non-root `node` user). The worker has no inbound
# port: liveness is a heartbeat file it rewrites each tick, and the health check fails once that heartbeat goes
# stale. Base image is digest-pinned (supply-chain gate).
FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS builder
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable
WORKDIR /repo
COPY . .
RUN pnpm install --frozen-lockfile \
 && pnpm run build \
 && pnpm deploy --legacy --filter=@pentest/worker --prod /app

FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS runtime
ENV NODE_ENV=production \
    WORKER_READINESS_FILE=/tmp/worker-ready
WORKDIR /app
COPY --from=builder /app ./
USER node
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=6 \
  CMD ["node","-e","const fs=require('fs');const f=process.env.WORKER_READINESS_FILE||'/tmp/worker-ready';process.exit(Date.now()-fs.statSync(f).mtimeMs<60000?0:1)"]
CMD ["node","dist/index.js"]
