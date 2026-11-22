FROM node:22.21-alpine@sha256:0340fa682d72068edf603c305bfbc10e23219fb0e40df58d9ea4d6f33a9798bf AS build
RUN corepack enable
WORKDIR /src
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm fetch
COPY . .
RUN pnpm install --offline --frozen-lockfile --filter @bae6/console...
RUN pnpm --filter @bae6/console build
# Only production dependencies and the adapter output reach the runtime image.
RUN pnpm --filter @bae6/console deploy --prod --legacy /app
RUN cp -r services/console/build /app/build

FROM node:22.21-alpine@sha256:0340fa682d72068edf603c305bfbc10e23219fb0e40df58d9ea4d6f33a9798bf
WORKDIR /app
COPY --from=build /app .
ENV NODE_ENV=production HOST=0.0.0.0 PORT=8080
USER node
CMD ["node", "build"]
