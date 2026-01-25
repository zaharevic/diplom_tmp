# Diplom Project (prototype)

Минимальный сервер приёма отчётов и коллектора для Linux/Windows.

- Server: FastAPI application in `server/app.py`.
- Collectors: `collector_linux.py`, `collector_windows.py` — собирают список ПО и отправляют JSON на сервер или сохраняют локально.

Запуск сервера

```bash
sudo chmod +x run-server.sh
./run-server.sh build
./run-server.sh start
```
