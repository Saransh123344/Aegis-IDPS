#!/bin/bash
echo "[AegisNet] Starting Full IDPS Pipeline..."

docker compose exec -T dpi_engine ./build/aegis_sniffer | while read -r line; do
    # Print every captured packet to the screen
    echo "$line"
    
    # Trigger the AI if plaintext OR URL-encoded SQL injection is found (%27 is an encoded apostrophe)
    if [[ "$line" == *"L7_PAYLOAD:"* ]] && ( [[ "$line" == *"'1'='1"* ]] || [[ "$line" == *"%27"* ]] || [[ "$line" == *"login.php"* ]] ); then
        echo -e "\n[CRITICAL THREAT] Suspicious payload intercepted! Forwarding to AI SOC...\n"
        cd ai_orchestrator
        
        # Use the absolute path to the Conda Python binary directly
        ~/miniconda/envs/aegis_ai/bin/python orchestrator.py "$line"
        
        cd ..
        
        # Stop sniffing temporarily while the AI investigates
        break 
    fi
done