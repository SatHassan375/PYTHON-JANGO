FROM python:3.9-slim as builder
# Set environment variables for non-buffered Python output
ENV PYTHONUNBUFFERED 1
# Set the working directory in the container for this stage
WORKDIR /app
# Copy the requirements.txt file into the container
COPY requirements.txt /app/
# Install dependencies in a temporary build environment
RUN pip install --no-cache-dir -r requirements.txt


# Stage 2: Production Stage
# Start from a new minimal image to create the final container image
FROM python:3.9-slim as production

# Set environment variables for non-buffered Python output
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /app

# Copy only the necessary installed dependencies from the build stage
COPY --from=build /root/.cache/pip /root/.cache/pip
COPY --from=build /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages

# Copy the rest of the project files into the container
COPY . /app/

# Expose port 8000 for the Django app
EXPOSE 8000


# Run migrations, create superuser, or any other setup (optional)
# CMD ["python", "manage.py", "migrate"]

# Start the Django development server (for production, you would typically use gunicorn)
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]