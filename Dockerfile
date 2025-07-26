FROM node:18-alpine

WORKDIR /app

COPY . .

RUN npm install express morgan express-rate-limit

CMD ["node", "index.js"]
