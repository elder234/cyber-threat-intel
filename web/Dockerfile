# syntax=docker/dockerfile:1

# Node 20 (Iron) reached EOL 2026-04-30 — no further security patches (see docs/SECURITY.md M5).
FROM node:22-alpine AS build
WORKDIR /app

# Install deps first (layer cache) then build.
COPY package.json package-lock.json* ./
RUN npm ci || npm install
COPY . .
RUN npm run build

# ----- runtime stage (static nginx) --------------------------------------
# nginx 1.27-alpine is below the fix line for the rewrite-module advisory
# (CVE-2026-9256, fixed in 1.28.3) — 1.28.x stable is used instead.
FROM nginx:1.28-alpine AS runtime

# SPA routing + API/WS proxy config.
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

# Run as the unprivileged nginx user (already present in the base image).
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
CMD ["nginx", "-g", "daemon off;"]
