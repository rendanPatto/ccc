#!/bin/bash
# Claude Bug Bounty — install skills into ~/.claude/skills/

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

INSTALL_DIR="${HOME}/.claude/skills"
mkdir -p "${INSTALL_DIR}"

echo "Installing Claude Bug Bounty skills..."
echo ""

# Copy all skills
for skill_dir in "${SCRIPT_DIR}"/skills/*/; do
    skill_name=$(basename "$skill_dir")
    mkdir -p "${INSTALL_DIR}/${skill_name}"
    cp "${skill_dir}SKILL.md" "${INSTALL_DIR}/${skill_name}/SKILL.md"
    echo "✓ Installed skill: ${skill_name}"
done

# Install commands
COMMANDS_DIR="${HOME}/.claude/commands"
mkdir -p "${COMMANDS_DIR}"

for cmd_file in "${SCRIPT_DIR}"/commands/*.md; do
    cmd_name=$(basename "$cmd_file")
    cp "$cmd_file" "${COMMANDS_DIR}/${cmd_name}"
    echo "✓ Installed command: ${cmd_name}"
done

# Install agents
AGENTS_DIR="${HOME}/.claude/agents/claude-bug-bounty"
mkdir -p "${AGENTS_DIR}"

for agent_file in "${SCRIPT_DIR}"/agents/*.md; do
    agent_name=$(basename "$agent_file")
    cp "$agent_file" "${AGENTS_DIR}/${agent_name}"
    echo "✓ Installed agent: ${agent_name}"
done

echo ""
echo "Done! Skills installed to ${INSTALL_DIR}"
echo "Commands installed to ${COMMANDS_DIR}"
echo "Agents installed to ${AGENTS_DIR}"
echo ""

# Offer Burp MCP setup
echo "─────────────────────────────────────────────"
echo "Optional: Burp Suite MCP Integration"
echo "─────────────────────────────────────────────"
echo ""
echo "Connect to PortSwigger's Burp MCP server for live HTTP traffic visibility."
echo "See mcp/burp-mcp-client/README.md for setup instructions."
echo ""
read -p "Set up Burp MCP now? (y/N): " setup_burp
if [[ "$setup_burp" =~ ^[Yy]$ ]]; then
    echo ""
    echo "To connect Burp MCP, add this to your Claude Code settings:"
    echo ""
    echo "  claude config edit"
    echo ""
    echo "Then add to the mcpServers section:"
    cat "${SCRIPT_DIR}/mcp/burp-mcp-client/config.json" | grep -A 10 '"burp"'
    echo ""
    echo "And set your Burp API key:"
    echo "  export BURP_API_KEY=\"your-api-key-here\""
    echo ""
fi

echo "Repo-local runtime:"
echo "  Claude Code should be launched from this repo so tools/ and memory/ paths resolve."
echo "  cd ${SCRIPT_DIR}"
echo "  claude"
echo ""
echo "Optional config:"
echo "  cp ${SCRIPT_DIR}/config.example.json ${SCRIPT_DIR}/config.json"
echo "  # set \"ctf_mode\": true for CTF / lab / local targets (unrestricted runtime, audit still logged)"
echo ""
echo "Start hunting:"
echo "  claude"
echo "  /recon target.com"
echo "  /hunt target.com"
echo "  /source-hunt target.com --repo-path /path/to/local/repo"
echo "  /autopilot target.com --normal"
echo ""
echo "Specialized agents:"
echo "  Installed under ${AGENTS_DIR}"
