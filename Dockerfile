# Dockerfile – usa l’immagine ufficiale Playwright con i browser già installati
FROM mcr.microsoft.com/playwright:v1.47.2-jammy

WORKDIR /app

# copia solo i manifest per la cache layer
COPY package*.json ./

# installa dipendenze (solo prod)
RUN npm install --omit=dev

# ora copia il resto del progetto
COPY . .

ENV NODE_ENV=production
# Render setta PORT in env, il tuo server la legge già (process.env.PORT)
# EXPOSE non è strettamente necessario ma non fa male
EXPOSE 8080

CMD ["node", "server.js"]
