#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI Threat Synthesizer - Threat Scenario Generation

Generates synthetic threat scenarios for testing and training.
Similar to FullScopeTest's AI Data Synthesizer but for security threats.

Example:
Input: "生成DDoS攻击测试数据"
Output: Synthetic PCAP data or traffic patterns mimicking DDoS attacks
"""

import json
import logging
import os
import re
import requests
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timedelta

from .config import get_ai_config

logger = logging.getLogger(__name__)


class AIThreatSynthesizer:
    """
    AI Threat Synthesizer for generating test data.

    Creates synthetic threat scenarios for testing detection rules.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize AI Threat Synthesizer.

        Args:
            config: Optional AI configuration
        """
        self.config = config or get_ai_config()

        # Common threat patterns
        self.threat_templates = {
            "ddos": {
                "name": "DDoS攻击",
                "description": "分布式拒绝服务攻击",
                "pattern": "high_volume_same_destination",
                "params": {"target_ip": "10.0.0.1", "packet_count": 10000}
            },
            "port_scan": {
                "name": "端口扫描",
                "description": "扫描多个端口寻找开放服务",
                "pattern": "sequential_port_access",
                "params": {"target_ip": "10.0.0.1", "port_range": "1-1024"}
            },
            "brute_force": {
                "name": "暴力破解",
                "description": "尝试多个密码组合",
                "pattern": "repeated_login_attempts",
                "params": {"target_ip": "10.0.0.1", "port": 22, "attempts": 100}
            },
            "sql_injection": {
                "name": "SQL注入",
                "description": "注入恶意SQL代码",
                "pattern": "malicious_http_payload",
                "params": {"target_url": "http://example.com/login"}
            }
        }

    def generate_scenario(
        self,
        threat_type: str,
        parameters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate a threat scenario.

        Args:
            threat_type: Type of threat (ddos, port_scan, brute_force, etc.)
            parameters: Optional custom parameters

        Returns:
            Generated scenario configuration
        """
        if not self.config.get('AI_ENABLED', True):
            return self._generate_fallback_scenario(threat_type, parameters)

        try:
            return self._generate_via_llm(threat_type, parameters or {})
        except Exception as exc:
            logger.warning(f"LLM场景生成失败，使用fallback: {exc}")
            return self._generate_fallback_scenario(threat_type, parameters)

    def _generate_via_llm(
        self,
        threat_type: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate scenario using LLM."""
        base_url = self.config.get('AI_BASE_URL', '').rstrip('/')
        if not base_url:
            raise ValueError("AI_BASE_URL为空")

        model = self.config.get('AI_MODEL', 'gpt-4o-mini')
        timeout = self.config.get('AI_TIMEOUT', 30)
        api_key = self.config.get('AI_API_KEY', '').strip()

        endpoint = f"{base_url}/chat/completions"

        system_prompt = (
            "你是一个网络安全测试场景生成专家。"
            "根据威胁类型生成详细的测试场景配置。"
            "返回JSON格式，不要使用markdown代码块。"
            "Schema: {"
            '"scenario_name":"场景名称",'
            '"threat_type":"威胁类型",'
            '"description":"场景描述",'
            '"traffic_pattern":{'
            '"packets_per_second":"每秒包数",'
            '"duration_seconds":"持续时间",'
            '"source_ips":["源IP列表"],'
            '"target_ip":"目标IP",'
            '"ports":"端口列表",'
            '"protocols":"协议列表"'
            '},'
            '"expected_signature":"预期特征",'
            '"detection_criteria":["检测标准"]'
            "}"
        )

        user_prompt = f"生成{threat_type}攻击测试场景"
        if parameters:
            user_prompt += f"\n参数: {json.dumps(parameters, ensure_ascii=False)}"

        payload = {
            "model": model,
            "temperature": 0.3,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }

        resp = requests.post(
            endpoint,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=timeout,
        )

        if resp.status_code >= 400:
            raise RuntimeError(f"LLM请求失败: HTTP {resp.status_code}")

        data = resp.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")

        # Parse JSON
        try:
            scenario = json.loads(content)
        except json.JSONDecodeError:
            match = re.search(r'\{[\s\S]*\}', content)
            scenario = json.loads(match.group(0)) if match else {}

        return self._normalize_scenario(scenario, threat_type)

    def _normalize_scenario(
        self,
        scenario: Dict[str, Any],
        threat_type: str
    ) -> Dict[str, Any]:
        """Normalize scenario structure."""
        return {
            "scenario_id": f"{threat_type}_{int(datetime.now().timestamp())}",
            "scenario_name": str(scenario.get("scenario_name", f"{threat_type}场景")).strip(),
            "threat_type": threat_type,
            "description": str(scenario.get("description", "")).strip(),
            "traffic_pattern": scenario.get("traffic_pattern", {}),
            "expected_signature": scenario.get("expected_signature", ""),
            "detection_criteria": scenario.get("detection_criteria", []),
            "generated_at": datetime.now().isoformat(),
        }

    def _generate_fallback_scenario(
        self,
        threat_type: str,
        parameters: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate scenario without LLM."""
        template = self.threat_templates.get(threat_type, {
            "name": f"{threat_type}攻击",
            "description": f"模拟{threat_type}攻击",
            "pattern": "generic_attack",
            "params": {}
        })

        params = {**template.get("params", {}), **(parameters or {})}

        return {
            "scenario_id": f"{threat_type}_{int(datetime.now().timestamp())}",
            "scenario_name": template["name"],
            "threat_type": threat_type,
            "description": template["description"],
            "traffic_pattern": {
                "pattern": template["pattern"],
                "params": params,
                "packets_per_second": 100,
                "duration_seconds": 60,
                "source_ips": [f"192.168.1.{i}" for i in range(2, 11)],
                "target_ip": params.get("target_ip", "10.0.0.1"),
                "ports": params.get("ports", [80, 443, 22]),
                "protocols": params.get("protocols", ["TCP"])
            },
            "expected_signature": f"{threat_type}_signature",
            "detection_criteria": [f"检测到{threat_type}特征"],
            "generated_at": datetime.now().isoformat(),
            "source": "fallback"
        }

    def generate_test_suite(
        self,
        threat_types: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Generate a test suite with multiple threat scenarios.

        Args:
            threat_types: List of threat types to include

        Returns:
            List of generated scenarios
        """
        scenarios = []
        for threat_type in threat_types:
            try:
                scenario = self.generate_scenario(threat_type)
                scenarios.append(scenario)
            except Exception as e:
                logger.error(f"生成{threat_type}场景失败: {e}")

        return scenarios

    def generate_variation(
        self,
        base_scenario: Dict[str, Any],
        variation_type: str = "mutate"
    ) -> Dict[str, Any]:
        """
        Generate a variation of an existing scenario.

        Args:
            base_scenario: Base scenario to vary
            variation_type: Type of variation (mutate, scale, mix)

        Returns:
            New scenario with variations
        """
        if not self.config.get('AI_ENABLED', True):
            return self._simple_variation(base_scenario, variation_type)

        # Create a variation based on type
        new_scenario = base_scenario.copy()
        new_scenario["scenario_id"] = f"{base_scenario['scenario_id']}_var"

        if variation_type == "scale":
            # Scale traffic volume
            pattern = new_scenario.get("traffic_pattern", {})
            pattern["packets_per_second"] = int(pattern.get("packets_per_second", 100) * 2)
            new_scenario["description"] = f"{base_scenario.get('description', '')} (放大版)"
        elif variation_type == "mutate":
            # Mutate parameters
            pattern = new_scenario.get("traffic_pattern", {})
            if "target_ip" in pattern:
                parts = pattern["target_ip"].split(".")
                parts[-1] = str(int(parts[-1]) + 1)
                pattern["target_ip"] = ".".join(parts)
            new_scenario["description"] = f"{base_scenario.get('description', '')} (变体)"

        return new_scenario

    def _simple_variation(
        self,
        base_scenario: Dict[str, Any],
        variation_type: str
    ) -> Dict[str, Any]:
        """Simple variation without LLM."""
        return self.generate_variation(base_scenario, variation_type)


# Test the threat synthesizer
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    synthesizer = AIThreatSynthesizer()

    # Example usage
    scenario = synthesizer.generate_scenario("ddos", {
        "target_ip": "10.0.0.100",
        "duration": 120
    })

    print(f"生成的场景: {json.dumps(scenario, indent=2, ensure_ascii=False)}")

    # Generate test suite
    suite = synthesizer.generate_test_suite(["ddos", "port_scan", "brute_force"])
    print(f"\n测试套件包含 {len(suite)} 个场景")
