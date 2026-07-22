# syntax=docker/dockerfile:1
# @pentest/web image: builds the static shell and serves it with a tiny dependency-free Node server that also
# exposes /healthz for the health check. Prod-only runtime via `pnpm deploy`, non-root `node` user. The container
# binds 0.0.0.0 on the internal compose network only — host exposure is loopback-only via docker-compose.
# Base image is digest-pinned (supply-chain gate).
FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS builder
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable
WORKDIR /repo
COPY . .
RUN pnpm install --frozen-lockfile \
 && pnpm run build \
 && pnpm deploy --legacy --filter=@pentest/web --prod /app

FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS runtime
ENV NODE_ENV=production \
    WEB_HOST=0.0.0.0 \
    WEB_PORT=8080
WORKDIR /app
COPY --from=builder /app ./
USER node
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=6 \
  CMD ["node","-e","require('http').get('http://127.0.0.1:'+(process.env.WEB_PORT||8080)+'/healthz',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"]
CMD ["node","serve.mjs"]
