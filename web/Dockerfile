# syntax=docker/dockerfile:1

# ----- build stage -------------------------------------------------------
FROM node:20-alpine AS build
WORKDIR /app

# Install deps first (layer cache) then build.
COPY package.json package-lock.json* ./
RUN npm ci || npm install
COPY . .
RUN npm run build

# ----- runtime stage (static nginx) --------------------------------------
FROM nginx:1.27-alpine AS runtime

# SPA routing + API/WS proxy config.
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

# Run as the unprivileged nginx user (already present in the base image).
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
CMD ["nginx", "-g", "daemon off;"]
