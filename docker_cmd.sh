docker run --name user-service -d --rm --network boh --env-file .env -p 5000:3001 boh/boh-user-management:v0 node /app/dist/backend.js
