#!/bin/bash
# Solodit MCP Helper Script
# Usage: ./solodit-helper.sh [command] [args]

SOLODIT_PORT=3000
SOLODIT_URL="http://localhost:$SOLODIT_PORT/mcp"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

start_server() {
    echo -e "${YELLOW}Starting Solodit MCP server...${NC}"
    
    # Check if already running
    if curl -s "$SOLODIT_URL" > /dev/null 2>&1; then
        echo -e "${GREEN}Server already running on port $SOLODIT_PORT${NC}"
        return 0
    fi
    
    # Start server in background
    npx -y @lyuboslavlyubenov/solodit-mcp &
    sleep 3
    
    if curl -s "$SOLODIT_URL" > /dev/null 2>&1; then
        echo -e "${GREEN}Server started successfully!${NC}"
    else
        echo -e "${RED}Failed to start server${NC}"
        return 1
    fi
}

stop_server() {
    echo -e "${YELLOW}Stopping Solodit MCP server...${NC}"
    pkill -f "solodit-mcp" 2>/dev/null
    echo -e "${GREEN}Server stopped${NC}"
}

search() {
    local keywords="$1"
    if [ -z "$keywords" ]; then
        echo -e "${RED}Usage: $0 search <keywords>${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}Searching for: $keywords${NC}"
    
    response=$(curl -s -X POST "$SOLODIT_URL" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"search\",\"arguments\":{\"keywords\":\"$keywords\"}}}")
    
    # Extract and format the results
    echo "$response" | grep -o 'data: {.*}' | sed 's/data: //' | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    findings = json.loads(data['result']['structuredContent']['reportsJSON'])
    print(f'\n📋 Found {len(findings)} results:\n')
    for i, f in enumerate(findings[:10], 1):
        print(f\"{i}. {f['title']}\")
        print(f\"   slug: {f['slug']}\n\")
except Exception as e:
    print(f'Error parsing response: {e}')
" 2>/dev/null || echo "$response"
}

get_report() {
    local slug="$1"
    if [ -z "$slug" ]; then
        echo -e "${RED}Usage: $0 get <slug>${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}Fetching report: $slug${NC}"
    
    curl -s -X POST "$SOLODIT_URL" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"get-by-slug\",\"arguments\":{\"slug\":\"$slug\"}}}"
}

case "$1" in
    start)
        start_server
        ;;
    stop)
        stop_server
        ;;
    search)
        search "$2"
        ;;
    get)
        get_report "$2"
        ;;
    *)
        echo "Solodit MCP Helper"
        echo ""
        echo "Usage: $0 <command> [args]"
        echo ""
        echo "Commands:"
        echo "  start           Start the Solodit MCP server"
        echo "  stop            Stop the Solodit MCP server"
        echo "  search <kw>     Search for vulnerabilities by keywords"
        echo "  get <slug>      Get full report by slug"
        echo ""
        echo "Examples:"
        echo "  $0 start"
        echo "  $0 search \"reentrancy\""
        echo "  $0 search \"oracle chainlink\""
        echo "  $0 get \"h-1-some-vulnerability-slug\""
        ;;
esac
