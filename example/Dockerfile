FROM node:22-alpine AS builder

WORKDIR /workspace

# Build local library so the example can install it via "file:..".
COPY package.json package-lock.json tsconfig.json ./
COPY src ./src
RUN npm ci
RUN npm run build

WORKDIR /workspace/example
COPY example/package.json example/package-lock.json ./
COPY example/nest-cli.json example/tsconfig.json example/tsconfig.build.json ./
RUN npm ci --install-links=false

COPY example/src ./src
RUN npm run build

FROM node:22-alpine AS runtime

WORKDIR /app
ENV NODE_ENV=production

COPY --from=builder /workspace/example/node_modules ./node_modules
COPY --from=builder /workspace/example/dist ./dist

# npm file dependencies can be symlinked as ../../ ; replace with a real package dir.
RUN rm -f ./node_modules/nestjs-keycloak-auth \
  && mkdir -p ./node_modules/nestjs-keycloak-auth

COPY --from=builder /workspace/package.json ./node_modules/nestjs-keycloak-auth/package.json
COPY --from=builder /workspace/dist ./node_modules/nestjs-keycloak-auth/dist

EXPOSE 3000

CMD ["node", "dist/src/main.js"]
