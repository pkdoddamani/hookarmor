FROM node:20-slim

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

# Create data directory for SQLite persistence and configure non-root ownership
RUN mkdir -p /app/data && chown -R node:node /app

USER node

EXPOSE 4000

ENV PORT=4000
ENV NODE_ENV=production

VOLUME ["/app/data"]

CMD ["node", "bin/hookarmor.js", "start"]
