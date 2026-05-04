ARG NODE_IMAGE=node:20-alpine
FROM ${NODE_IMAGE}

ARG INSTALL_DEPS=true

WORKDIR /app
COPY package.json package-lock.json* ./
RUN if [ "$INSTALL_DEPS" = "true" ]; then \
      if [ -f package-lock.json ]; then npm ci; else npm install; fi; \
    fi

COPY . .

RUN npm run build

CMD ["npm", "run", "dev"]
