FROM node:18-alpine

RUN apk update && apk upgrade --no-cache

WORKDIR /app

COPY . .

RUN npm install express morgan express-rate-limit

CMD ["node", "index.js"]
