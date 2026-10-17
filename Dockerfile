FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && apk add --no-cache libcap && setcap cap_net_bind_service=+ep /usr/local/bin/node && apk del libcap
COPY server.js hash-password.js ./
COPY assets ./assets
RUN mkdir -p /data && chown node:node /data
USER node
ENV NODE_ENV=production PORT=80 DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1/healthz || exit 1
CMD ["node", "server.js"]
