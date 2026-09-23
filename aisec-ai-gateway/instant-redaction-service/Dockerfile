# Use official Python base image
FROM python:3.11-slim

# Create app directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    tesseract-ocr \
    libglib2.0-0 \
    libsm6 \
    libxrender1 \
    libxext6 \
    libgl1 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install spaCy English model before running code
RUN pip install --upgrade pip
COPY requirements.txt .
RUN pip install -r requirements.txt

# Download spaCy model (must match what's in requirements.txt)
RUN python -m spacy download en_core_web_lg

# Copy code
COPY . .

EXPOSE 8001

# Run the app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
