FROM python:3.11-slim
WORKDIR /app
# requirements.txt is in the repository root; when building with context='.' copy it from there
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
# copy server sources into image
COPY . /app
EXPOSE 8000
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000"]
