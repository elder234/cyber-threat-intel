# ── Aegis API — multi-stage build ───────────────────────────────────────────
# NOTE: build context is the REPO ROOT (see docker-compose.yml) so we can copy
# both services/api and the shared db/ migrations into the image.
FROM node:20-alpine AS build
WORKDIR /app

# argon2 needs a build toolchain for its native addon
RUN apk add --no-cache python3 make g++

COPY services/api/package.json ./
RUN npm install --no-audit --no-fund

COPY services/api/tsconfig.json ./
COPY services/api/src ./src
RUN npm run build

# Prune to production deps (keeps compiled argon2 binding)
RUN npm prune --omit=dev

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

RUN addgroup -S aegis && adduser -S aegis -G aegis

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./
# Migrations are read at runtime. migrate.js lives at /app/dist/db/migrate.js and
# resolves ../../../../db/migrations => /db/migrations, so copy them there.
COPY --chown=aegis:aegis db /db

USER aegis
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --retries=5 \
  CMD node -e "fetch('http://localhost:8080/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/server.js"]
