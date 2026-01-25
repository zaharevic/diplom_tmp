#!/bin/bash
set -e

# Configuration
IMAGE_NAME="vuln-collector"
CONTAINER_NAME="vuln-collector"
PORT=8000
DATA_DIR="${DATA_DIR:-.data}"
SERVER_DIR="server"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
print_usage() {
    echo "Usage: $0 {build|run|stop|logs|shell|db|cleanup}"
    echo ""
    echo "Commands:"
    echo "  build          - Build Docker image"
    echo "  run            - Run container (build if needed)"
    echo "  stop           - Stop running container"
    echo "  logs           - Show container logs"
    echo "  shell          - Open interactive shell in running container"
    echo "  db             - Query database (check reports and software)"
    echo "  clean-cache    - Clear NVD API cache (keeps reports and software)"
    echo "  clean-db       - Delete all data (reports, software, cache)"
    echo "  cleanup        - Remove container and image"
    echo ""
    echo "Environment variables:"
    echo "  DATA_DIR      - Local directory to mount for reports (default: .data)"
    echo "  API_KEY       - API key for authentication (default: change-me-secret-key)"
    echo "  NVD_API_KEY   - NVD API key for higher rate limits (optional)"
    echo "  PORT          - Port to expose (default: 8000)"
}

build_image() {
    echo -e "${YELLOW}[*] Building Docker image: ${IMAGE_NAME}${NC}"
    docker build -f ${SERVER_DIR}/Dockerfile -t ${IMAGE_NAME} ${SERVER_DIR}
    echo -e "${GREEN}[+] Image built successfully${NC}"
}

run_container() {
    # Check if image exists
    if ! docker image inspect ${IMAGE_NAME} > /dev/null 2>&1; then
        echo -e "${YELLOW}[*] Image not found, building...${NC}"
        build_image
    fi

    # Stop existing container if running
    if docker ps --filter "name=${CONTAINER_NAME}" --format "{{.Names}}" | grep -q ${CONTAINER_NAME}; then
        echo -e "${YELLOW}[*] Stopping existing container...${NC}"
        docker stop ${CONTAINER_NAME}
    fi

    # Create data directory
    mkdir -p ${DATA_DIR}

    echo -e "${YELLOW}[*] Starting container: ${CONTAINER_NAME}${NC}"
    
    # Build docker run command with env file support
    if [ -f ".env" ]; then
        docker run \
            --rm \
            -d \
            --name ${CONTAINER_NAME} \
            -p ${PORT}:8000 \
            -v ${PWD}/${DATA_DIR}:/data/reports \
            --env-file .env \
            -e DB_PATH="/data/reports/vuln_collector.db" \
            -e DATA_DIR="/data/reports" \
            ${IMAGE_NAME}
    else
        docker run \
            --rm \
            -d \
            --name ${CONTAINER_NAME} \
            -p ${PORT}:8000 \
            -v ${PWD}/${DATA_DIR}:/data/reports \
            -e API_KEY="${API_KEY}" \
            -e NVD_API_KEY="${NVD_API_KEY}" \
            -e DB_PATH="/data/reports/vuln_collector.db" \
            -e DATA_DIR="/data/reports" \
            ${IMAGE_NAME}
    fi

    sleep 2
    echo -e "${GREEN}[+] Container running${NC}"
    echo -e "${GREEN}[+] Server available at http://localhost:${PORT}${NC}"
    
    if [ -f ".env" ]; then
        echo -e "${GREEN}[+] Configuration loaded from .env${NC}"
        if grep -q "NVD_API_KEY=" .env; then
            echo -e "${GREEN}[+] NVD_API_KEY: configured (120 req/min rate limit)${NC}"
        else
            echo -e "${YELLOW}[!] NVD_API_KEY: not set (10 req/min rate limit)${NC}"
        fi
    else
        echo -e "${YELLOW}[!] .env not found, using defaults${NC}"
        echo -e "${YELLOW}[!] Copy .env.example to .env and add your keys${NC}"
    fi
    echo -e "${GREEN}[+] Data directory: ${DATA_DIR}${NC}"
}

stop_container() {
    if docker ps --filter "name=${CONTAINER_NAME}" --format "{{.Names}}" | grep -q ${CONTAINER_NAME}; then
        echo -e "${YELLOW}[*] Stopping container: ${CONTAINER_NAME}${NC}"
        docker stop ${CONTAINER_NAME}
        echo -e "${GREEN}[+] Container stopped${NC}"
    else
        echo -e "${YELLOW}[-] Container not running${NC}"
    fi
}

show_logs() {
    echo -e "${YELLOW}[*] Showing container logs (last 100 lines)${NC}"
    docker logs --tail 100 ${CONTAINER_NAME}
}

open_shell() {
    if ! docker ps --filter "name=${CONTAINER_NAME}" --format "{{.Names}}" | grep -q ${CONTAINER_NAME}; then
        echo -e "${RED}[-] Container not running${NC}"
        exit 1
    fi
    echo -e "${YELLOW}[*] Opening shell in container...${NC}"
    docker exec -it ${CONTAINER_NAME} /bin/sh
}

query_db() {
    if ! docker ps --filter "name=${CONTAINER_NAME}" --format "{{.Names}}" | grep -q ${CONTAINER_NAME}; then
        echo -e "${RED}[-] Container not running${NC}"
        exit 1
    fi
    echo -e "${YELLOW}[*] Querying database...${NC}"
    docker exec ${CONTAINER_NAME} sqlite3 /data/reports/vuln_collector.db << 'EOF'
.mode column
.headers on
SELECT '=== REPORTS ===' as info;
SELECT id, hostname, ip, os, collected_at FROM reports ORDER BY id DESC LIMIT 10;
SELECT '=== REPORTS COUNT ===' as info;
SELECT COUNT(*) as total_reports FROM reports;
SELECT '=== SOFTWARE COUNT BY HOST ===' as info;
SELECT hostname, COUNT(*) as software_count FROM software GROUP BY hostname;
SELECT '=== SAMPLE SOFTWARE ===' as info;
SELECT hostname, name, version FROM software LIMIT 10;
EOF
}

cleanup() {
    echo -e "${YELLOW}[*] Cleaning up...${NC}"
    stop_container
    if docker image inspect ${IMAGE_NAME} > /dev/null 2>&1; then
        echo -e "${YELLOW}[*] Removing image: ${IMAGE_NAME}${NC}"
        docker rmi ${IMAGE_NAME}
    fi
    echo -e "${GREEN}[+] Cleanup complete${NC}"
}

clean_cache() {
    echo -e "${YELLOW}[*] Clearing NVD API cache...${NC}"
    ./run-server.sh db "DELETE FROM cve_cache;"
    echo -e "${GREEN}[+] NVD API cache cleared${NC}"
    echo -e "${GREEN}[+] Reports and software data preserved${NC}"
}

clean_db() {
    echo -e "${RED}[!] WARNING: This will delete ALL data (reports, software, cache)${NC}"
    read -p "Are you sure? Type 'yes' to confirm: " confirm
    if [ "$confirm" = "yes" ]; then
        echo -e "${YELLOW}[*] Deleting all data...${NC}"
        ./run-server.sh db "DELETE FROM cve_cache; DELETE FROM software; DELETE FROM reports;"
        echo -e "${GREEN}[+] All data deleted${NC}"
    else
        echo -e "${YELLOW}[!] Cancelled${NC}"
    fi
}

# Main
if [ $# -eq 0 ]; then
    print_usage
    exit 0
fi

case "$1" in
    build)
        build_image
        ;;
    run)
        run_container
        ;;
    stop)
        stop_container
        ;;
    logs)
        show_logs
        ;;
    shell)
        open_shell
        ;;
    db)
        query_db
        ;;
    clean-cache)
        clean_cache
        ;;
    clean-db)
        clean_db
        ;;
    cleanup)
        cleanup
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        print_usage
        exit 1
        ;;
esac
