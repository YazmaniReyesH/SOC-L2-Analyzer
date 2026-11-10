# Frontend SOC L2 Analyzer — Vite dev server (modo desarrollo).
FROM node:20-slim

WORKDIR /app

COPY package.json ./
RUN npm install

COPY . .

EXPOSE 5173

# host 0.0.0.0 para que sea accesible desde fuera del contenedor.
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
