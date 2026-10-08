FROM node:20-slim

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

ENTRYPOINT ["/app/bin/docker-entrypoint.sh"]
CMD ["node", "bin/hookarmor.js", "start"]
