#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI Agents Configuration

Configuration for AI components including API keys, model settings, and tool definitions.
"""

import os
from typing import Dict, Any, List

# AI Configuration
AI_CONFIG = {
    # Default LLM settings
    'AI_BASE_URL': os.getenv('AI_BASE_URL', 'https://api.deepseek.com/v1'),
    'AI_MODEL': os.getenv('AI_MODEL', 'deepseek-chat'),
    'AI_API_KEY': os.getenv('AI_API_KEY', ''),
    'AI_TIMEOUT': int(os.getenv('AI_TIMEOUT', '30')),

    # Vision model settings (for web explorer)
    'AI_VISION_BASE_URL': os.getenv('AI_VISION_BASE_URL', 'https://api.openai.com/v1'),
    'AI_VISION_MODEL': os.getenv('AI_VISION_MODEL', 'gpt-4o'),
    'AI_VISION_API_KEY': os.getenv('AI_VISION_API_KEY', ''),

    # Feature flags
    'AI_ENABLED': os.getenv('AI_ENABLED', 'true').lower() == 'true',
    'AI_MOCK_MODE': False,  # 设置为False启用真实AI模式，需要API密钥
}


# Function Calling Tools for AI Copilot
AI_TOOLS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "boost_network_speed",
            "description": "Increase network speed for better performance. Use this when user asks to make network faster, increase bandwidth, or improve speed.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "enum": ["all", "specific"],
                        "description": "Target: 'all' for entire network or 'specific' for specific host"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "limit_network_speed",
            "description": "Limit network speed for QoS control. Use this when user asks to limit speed, throttle bandwidth, or apply rate limiting.",
            "parameters": {
                "type": "object",
                "properties": {
                    "bandwidth_mbps": {
                        "type": "number",
                        "description": "Bandwidth limit in Mbps (e.g., 0.2 for 200Kbps, 1 for 1Mbps)"
                    },
                    "target_ip": {
                        "type": "string",
                        "description": "Target IP address (optional, will auto-detect if not provided)"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_network_topology",
            "description": "Get current network topology including switches and hosts. Use this when user asks about network structure, topology, or connected devices.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "block_ip_address",
            "description": "Block a specific IP address to prevent attacks. Use this when user asks to block or blacklist an IP.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip_address": {
                        "type": "string",
                        "description": "The IP address to block (e.g., 192.168.1.100)"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason for blocking this IP"
                    }
                },
                "required": ["ip_address"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "unblock_ip_address",
            "description": "Unblock a previously blocked IP address. Use this when user asks to unblock or whitelist an IP.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip_address": {
                        "type": "string",
                        "description": "The IP address to unblock (e.g., 192.168.1.100)"
                    }
                },
                "required": ["ip_address"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_network_stats",
            "description": "Get current network statistics including traffic, protocols, and threat information.",
            "parameters": {
                "type": "object",
                "properties": {
                    "timeframe": {
                        "type": "string",
                        "enum": ["hour", "day", "week"],
                        "description": "Time range for statistics (default: hour)"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_recent_threats",
            "description": "Get recent detected threats and attacks. Use this when user asks about recent threats or attacks.",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Number of recent threats to return (default: 10, max: 100)"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["高", "中", "低"],
                        "description": "Filter by severity level"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_pcap_file",
            "description": "Analyze a PCAP file for threats. Use this when user asks to analyze a pcap file or network capture.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Name of the PCAP file to analyze"
                    }
                },
                "required": ["filename"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_alerts",
            "description": "Get recent security alerts. Use this when user asks about alerts or notifications.",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Number of alerts to return (default: 20)"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["高", "中", "低"],
                        "description": "Filter by severity level"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "set_monitoring_mode",
            "description": "Set the network monitoring mode. Use this when user asks to change monitoring or detection mode.",
            "parameters": {
                "type": "object",
                "properties": {
                    "mode": {
                        "type": "string",
                        "enum": ["passive", "active", "learning"],
                        "description": "Monitoring mode: passive (observe only), active (block threats), learning (collect data)"
                    }
                },
                "required": ["mode"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_system_status",
            "description": "Get the current system status including running state, processed packets, and blocked attacks.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "generate_detection_report",
            "description": "Generate a comprehensive threat detection report. Use this when user asks for a report or summary.",
            "parameters": {
                "type": "object",
                "properties": {
                    "timeframe": {
                        "type": "string",
                        "enum": ["hour", "day", "week"],
                        "description": "Time range for the report (default: day)"
                    }
                }
            }
        }
    },
]

def get_ai_config() -> Dict[str, Any]:
    """Get AI configuration with defaults and load from file if available."""
    import os
    import json

    config = AI_CONFIG.copy()

    # Try to load from config file (at root level)
    # Get the root directory by going up from modules/ai_agents
    root_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    config_file = os.path.join(root_dir, 'data', 'ai_config.json')

    try:
        if os.path.exists(config_file):
            with open(config_file, 'r', encoding='utf-8') as f:
                saved_config = json.load(f)
                # Update config with saved values
                for key, value in saved_config.items():
                    if isinstance(value, str) and value.strip():  # Only use non-empty string values
                        config[key] = value.strip()
                    elif value is not None:  # Use non-None values
                        config[key] = value
                print(f"Loaded AI config from file: {list(saved_config.keys())}")
                print(f"API Key loaded: {config.get('AI_API_KEY', 'N/A')[:20]}...")
    except Exception as e:
        print(f"Warning: Failed to load AI config from file: {e}")
        print(f"Config file path: {config_file}")

    return config

def get_ai_tools() -> List[Dict[str, Any]]:
    """Get available AI tools for function calling."""
    return AI_TOOLS.copy()

def update_ai_config(key: str, value: Any) -> None:
    """Update AI configuration at runtime."""
    AI_CONFIG[key] = value

def enable_mock_mode(enable: bool = True) -> None:
    """Enable or disable mock mode for testing."""
    AI_CONFIG['AI_MOCK_MODE'] = enable
    if enable:
        AI_CONFIG['AI_ENABLED'] = True
