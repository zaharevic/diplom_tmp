FROM python:3.11-slim
WORKDIR /app
# requirements.txt is in the server/ folder (same level as Dockerfile)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
# copy server sources into image
COPY . /app
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
