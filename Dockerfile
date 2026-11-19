# AllWA multi-user WhatsApp panel — Render free web service (or any Docker host)
FROM node:22-slim

WORKDIR /app

# Install production dependencies first (better layer caching)
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# App code (server + panel frontend)
COPY server.js ./
COPY public ./public

# Render (and most hosts) inject the port to listen on
ENV NODE_ENV=production
EXPOSE 8791

CMD ["node", "server.js"]
