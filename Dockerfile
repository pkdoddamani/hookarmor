FROM node:22-slim

# Install gosu for secure runtime privilege dropping from root to unprivileged 'node' user
RUN apt-get update && apt-get install -y --no-install-recommends gosu && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

# Prepare data directory, entrypoint script permissions, and app ownership
RUN mkdir -p /app/data && chown -R node:node /app && chmod +x /app/bin/docker-entrypoint.sh

EXPOSE 4000

ENV PORT=4000
ENV NODE_ENV=production

# Lets `docker ps` and orchestrators see a wedged process (slim images have no curl)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 4000) + '/healthz').then((r) => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

ENTRYPOINT ["/app/bin/docker-entrypoint.sh"]
CMD ["node", "bin/hookarmor.js", "start"]
