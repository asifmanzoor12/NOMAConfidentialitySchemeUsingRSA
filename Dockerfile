# Use the official Python image as base
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /app

# Install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Flask application code
COPY . /app/

# Expose port 5000
EXPOSE 5000

# Run the Flask application
CMD ["python", "app.py"]
