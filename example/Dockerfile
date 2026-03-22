FROM node:22-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
COPY nest-cli.json tsconfig.json tsconfig.build.json ./
RUN npm ci

COPY src ./src
RUN npm run build

FROM node:22-alpine AS runtime

WORKDIR /app
ENV NODE_ENV=production

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist

EXPOSE 3000

CMD ["node", "dist/src/main.js"]
