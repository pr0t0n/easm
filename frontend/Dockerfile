FROM node:20-alpine

WORKDIR /app
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

COPY . .

RUN npm run build

CMD ["npm", "run", "dev"]
