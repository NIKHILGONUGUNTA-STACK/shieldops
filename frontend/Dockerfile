# Multi-stage production build for Aegis SOC Angular Dashboard
# Stage 1: Build
FROM node:22-alpine AS builder

WORKDIR /app

# Cache dependency layer
COPY package.json package-lock.json ./
RUN npm ci --prefer-offline --no-audit

# Copy application sources
COPY . .

# Compile Angular production bundle
RUN npm run build -- --configuration=production

# Stage 2: Hardened unprivileged Nginx runtime
FROM nginxinc/nginx-unprivileged:1.27-alpine

USER root
# Ensure directory permissions for non-root nginx user
RUN rm -rf /usr/share/nginx/html/* && \
    mkdir -p /usr/share/nginx/html && \
    chown -R 101:101 /usr/share/nginx/html /var/cache/nginx /var/log/nginx /etc/nginx/conf.d

USER 101

# Copy compiled SPA static assets from builder stage
COPY --from=builder --chown=101:101 /app/dist/aegis-frontend/browser /usr/share/nginx/html

# Copy production Nginx reverse-proxy & security configuration
COPY --chown=101:101 nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -q -O - http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["nginx", "-g", "daemon off;"]
