# Gebruik een lightweight Python-image
FROM python:3.9-slim

# Stel de Workdir in
WORKDIR /app

# Copy de reqs.txt en de code
COPY requirements.txt requirements.txt
COPY . .

# Instal Python-dependecies
RUN pip install --no-cache-dir -r requirements.txt

# Stel de poort in waarop app gaat  draaien
EXPOSE 5000

# Start de app
CMD ["python", "application.py"]

