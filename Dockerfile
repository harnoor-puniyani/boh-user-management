FROM node:25-alpine as builder
WORKDIR /app

COPY package*.json ./

RUN npm ci

COPY . .

RUN npm run build

FROM node:25-alpine as prod

WORKDIR /app

COPY package*.json ./

COPY --from=buildeer /app/dist ./dist

EXPOSE 3000

CMD ["node","dist/index.js"]