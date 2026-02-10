FROM python:3.12-slim

# Install system dependencies for ping and snmpwalk
RUN apt-get update && apt-get install -y \
    iputils-ping \
    snmp \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY network_api.py .

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "network_api.py"]
