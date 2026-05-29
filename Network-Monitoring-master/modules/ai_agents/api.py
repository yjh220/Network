#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI Agents API Routes

Flask API endpoints for AI agent functionality.
Integrates with the main Network-Monitoring application.
"""

import json
import logging
from flask import Blueprint, request, jsonify, render_template
from typing import Dict, Any

from .copilot import AICopilot
from .planner import AIPlanner
from .rule_generator import AIRuleGenerator
from .rule_healer import AIRuleHealer
from .threat_synthesizer import AIThreatSynthesizer
from .config import update_ai_config, get_ai_config

logger = logging.getLogger(__name__)

# Create Blueprint
ai_agents_bp = Blueprint('ai_agents', __name__, url_prefix='/api/ai')

# Initialize AI agents
copilot = None
planner = None
rule_generator = None
rule_healer = None
threat_synthesizer = None


def init_ai_agents(app=None):
    """Initialize AI agents with app context."""
    global copilot, planner, rule_generator, rule_healer, threat_synthesizer

    config = get_ai_config()

    copilot = AICopilot(config)
    planner = AIPlanner(config)
    rule_generator = AIRuleGenerator(config)
    rule_healer = AIRuleHealer(config)
    threat_synthesizer = AIThreatSynthesizer(config)

    # Register tool handlers with actual system functions
    if app:
        _register_system_handlers(app)

    logger.info("AI Agents initialized")


def _register_system_handlers(app):
    """Register actual system handlers with the copilot."""
    if not copilot:
        return

    # Import system modules (avoid circular imports)
    from modules.intrusion_prevention.prevention import IntrusionPrevention
    from modules.network_monitoring.monitor import NetworkMonitor
    from modules.alert_response.alerter import AlertSystem
    from modules.threat_find.ThreatFind import ThreatFind

    # Get system instances from app
    prevention = getattr(app, 'prevention', None)
    monitor = getattr(app, 'monitor', None)
    alert_system = getattr(app, 'alert_system', None)
    threat_find = getattr(app, 'threat_find', None)

    # Register handlers
    if prevention:
        copilot.register_tool_handler('block_ip_address', prevention.block_ip)
        copilot.register_tool_handler('unblock_ip_address', prevention.unblock_ip)

    if monitor:
        copilot.register_tool_handler('get_network_stats', monitor.get_network_stats)
        copilot.register_tool_handler('get_system_status', lambda: {
            "status": "success",
            "message": "系统运行正常",
            "system_status": getattr(app, 'system_status', {})
        })

    if alert_system:
        copilot.register_tool_handler('get_alerts', alert_system.get_recent_alerts)
        copilot.register_tool_handler('get_recent_threats', alert_system.get_recent_alerts)

    if threat_find:
        copilot.register_tool_handler('analyze_pcap_file', threat_find.extractFeature)

    logger.info("System handlers registered with AI Copilot")


# ==================== Web UI Routes ====================

@ai_agents_bp.route('/copilot')
def copilot_page():
    """AI Copilot chat interface."""
    return render_template('ai_copilot.html')


@ai_agents_bp.route('/planner')
def planner_page():
    """AI Planner interface."""
    return render_template('ai_planner.html')


@ai_agents_bp.route('/rules')
def rules_page():
    """AI Rule Generator interface."""
    return render_template('ai_rules.html')


# ==================== API Routes ====================

@ai_agents_bp.route('/config', methods=['GET', 'POST'])
def ai_config():
    """Get or update AI configuration."""
    if request.method == 'POST':
        data = request.get_json() or {}
        for key, value in data.items():
            update_ai_config(key, value)
        return jsonify({'success': True, 'config': get_ai_config()})
    return jsonify({'success': True, 'config': get_ai_config()})


@ai_agents_bp.route('/chat', methods=['POST'])
def chat():
    """
    AI Copilot chat endpoint.

    Request:
    {
        "message": "User message",
        "history": [...]
    }

    Response:
    {
        "success": true,
        "reply": "AI response",
        "tool_calls": [...]
    }
    """
    if not copilot:
        return jsonify({'success': False, 'error': 'AI Copilot未初始化'}), 500

    data = request.get_json() or {}
    message = data.get('message', '').strip()
    history = data.get('history', [])

    if not message:
        return jsonify({'success': False, 'error': 'message不能为空'}), 400

    try:
        response = copilot.chat(message, history)
        return jsonify(response)
    except Exception as e:
        logger.error(f"Chat error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@ai_agents_bp.route('/plan', methods=['POST'])
def generate_plan():
    """
    AI Planner endpoint.

    Request:
    {
        "prompt": "Generate detection plan for port scan",
        "context": {...}
    }

    Response:
    {
        "success": true,
        "plan": {
            "summary": "Plan summary",
            "operations": [...]
        }
    }
    """
    if not planner:
        return jsonify({'success': False, 'error': 'AI Planner未初始化'}), 500

    data = request.get_json() or {}
    prompt = data.get('prompt', '').strip()
    context = data.get('context', {})

    if not prompt:
        return jsonify({'success': False, 'error': 'prompt不能为空'}), 400

    try:
        plan = planner.generate_plan(prompt, context)
        return jsonify({'success': True, 'plan': plan})
    except Exception as e:
        logger.error(f"Plan generation error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@ai_agents_bp.route('/rules/generate', methods=['POST'])
def generate_rule():
    """
    AI Rule Generator endpoint.

    Request:
    {
        "prompt": "Generate rule for SSH brute force",
        "rule_type": "detection|prevention|alert"
    }

    Response:
    {
        "success": true,
        "rule": {...}
    }
    """
    if not rule_generator:
        return jsonify({'success': False, 'error': 'AI Rule Generator未初始化'}), 500

    data = request.get_json() or {}
    prompt = data.get('prompt', '').strip()
    rule_type = data.get('rule_type', 'detection')

    if not prompt:
        return jsonify({'success': False, 'error': 'prompt不能为空'}), 400

    try:
        rule = rule_generator.generate_rule(prompt, rule_type)
        return jsonify({'success': True, 'rule': rule})
    except Exception as e:
        logger.error(f"Rule generation error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@ai_agents_bp.route('/rules/fix', methods=['POST'])
def fix_rule():
    """
    AI Rule Healer endpoint.

    Request:
    {
        "rule": {...},
        "error": "Error message",
        "context": {...}
    }

    Response:
    {
        "success": true,
        "diagnosis": {
            "diagnosis": "...",
            "fixed_rule": {...}
        }
    }
    """
    if not rule_healer:
        return jsonify({'success': False, 'error': 'AI Rule Healer未初始化'}), 500

    data = request.get_json() or {}
    rule = data.get('rule', {})
    error = data.get('error', '')
    context = data.get('context', {})

    if not rule or not error:
        return jsonify({'success': False, 'error': 'rule和error不能为空'}), 400

    try:
        diagnosis = rule_healer.diagnose_and_fix(rule, error, context)
        return jsonify({'success': True, 'diagnosis': diagnosis})
    except Exception as e:
        logger.error(f"Rule fix error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@ai_agents_bp.route('/threats/synthesize', methods=['POST'])
def synthesize_threat():
    """
    AI Threat Synthesizer endpoint.

    Request:
    {
        "threat_type": "ddos|port_scan|brute_force",
        "parameters": {...}
    }

    Response:
    {
        "success": true,
        "scenario": {...}
    }
    """
    if not threat_synthesizer:
        return jsonify({'success': False, 'error': 'AI Threat Synthesizer未初始化'}), 500

    data = request.get_json() or {}
    threat_type = data.get('threat_type', '').strip()
    parameters = data.get('parameters', {})

    if not threat_type:
        return jsonify({'success': False, 'error': 'threat_type不能为空'}), 400

    try:
        scenario = threat_synthesizer.generate_scenario(threat_type, parameters)
        return jsonify({'success': True, 'scenario': scenario})
    except Exception as e:
        logger.error(f"Threat synthesis error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@ai_agents_bp.route('/health', methods=['GET'])
def health_check():
    """Check AI agents health status."""
    return jsonify({
        'success': True,
        'status': 'healthy',
        'components': {
            'copilot': copilot is not None,
            'planner': planner is not None,
            'rule_generator': rule_generator is not None,
            'rule_healer': rule_healer is not None,
            'threat_synthesizer': threat_synthesizer is not None,
        },
        'ai_enabled': get_ai_config().get('AI_ENABLED', False)
    })
