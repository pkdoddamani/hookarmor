FROM node:20-slim

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

# Create data directory for SQLite persistence
RUN mkdir -p /app/data

EXPOSE 4000

ENV PORT=4000
ENV NODE_ENV=production
ENV HOOKARMOR_DATA_DIR=/app/data

CMD ["node", "bin/hookarmor.js", "start"]
