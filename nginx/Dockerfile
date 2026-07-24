# ─────────────────────────────────────────────────────────────────────────────
# Aegis CTI — Nginx image with SPA static assets baked in.
# Expects the frontend image (aegis-cti/frontend:local) to be built first;
# docker-compose handles ordering via depends_on.
# ─────────────────────────────────────────────────────────────────────────────
FROM aegis-cti/frontend:local AS frontend

FROM nginx:1.27-alpine

# Remove default site
RUN rm -rf /usr/share/nginx/html/*

# Copy SPA build output from the frontend image
COPY --from=frontend /app/dist /usr/share/nginx/html

# Custom nginx config
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
