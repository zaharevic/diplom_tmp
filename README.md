# Diplom Project (prototype)

Минимальный сервер приёма отчётов и коллектора для Linux/Windows.

- Server: FastAPI application in `server/app.py`.
- Collectors: `collector_linux.py`, `collector_windows.py` — собирают список ПО и отправляют JSON на сервер или сохраняют локально.

Как запустить сервер локально (без Docker):

```bash
python server/app.py
```

Docker:

```bash
docker build -t vuln-collector-server -f server/Dockerfile server
docker run -p 8000:8000 -v /path/to/data:/data/reports vuln-collector-server
```
