#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI Agents Module for Network-Monitoring

This module integrates AI capabilities from FullScopeTest into the Network-Monitoring system,
providing intelligent network security monitoring and threat detection.

Components:
- AI Copilot: Natural language interface for security operations
- AI Planner: Natural language to detection plan generation
- AI Rule Generator: Natural language to detection rule generation
- AI Rule Healer: Automatic rule error fixing
- AI Threat Synthesizer: Threat scenario generation

Author: Integrated from FullScopeTest AI Framework
"""

from .copilot import AICopilot
from .planner import AIPlanner
from .rule_generator import AIRuleGenerator
from .rule_healer import AIRuleHealer
from .threat_synthesizer import AIThreatSynthesizer

__all__ = [
    'AICopilot',
    'AIPlanner',
    'AIRuleGenerator',
    'AIRuleHealer',
    'AIThreatSynthesizer'
]

__version__ = '1.0.0'
