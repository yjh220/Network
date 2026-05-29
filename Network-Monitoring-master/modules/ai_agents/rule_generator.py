#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI Rule Generator - Natural Language to Detection Rules

Converts natural language descriptions into executable detection rules.
Similar to FullScopeTest's AI Script Generator but for network security rules.

Example:
Input: "检测来自外部IP的SSH暴力破解，一分钟内超过10次连接尝试"
Output: Executable detection rule with conditions and actions
"""

import json
import logging
import os
import re
import requests
from typing import Dict, Any, List, Optional

from .config import get_ai_config

logger = logging.getLogger(__name__)


class AIRuleGenerator:
    """
    AI Rule Generator for threat detection rules.

    Converts natural language into detection rule configurations.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize AI Rule Generator.

        Args:
            config: Optional AI configuration
        """
        self.config = config or get_ai_config()

    def generate_rule(
        self,
        prompt: str,
        rule_type: str = "detection"
    ) -> Dict[str, Any]:
        """
        Generate a detection rule from natural language.

        Args:
            prompt: Natural language description
            rule_type: Type of rule (detection, prevention, alert)

        Returns:
            Generated rule configuration
        """
        text = (prompt or "").strip()
        if not text:
            raise ValueError("prompt不能为空")

        if not self.config.get('AI_ENABLED', True):
            raise ValueError("AI功能未启用")

        api_key = self.config.get('AI_API_KEY', '').strip()
        if not api_key:
            raise ValueError("AI_API_KEY未配置")

        try:
            return self._generate_via_llm(text, rule_type)
        except Exception as exc:
            logger.error(f"AI规则生成失败: {exc}")
            raise RuntimeError(f"规则生成失败: {str(exc)}")

    def _generate_via_llm(
        self,
        prompt: str,
        rule_type: str
    ) -> Dict[str, Any]:
        """Generate rule using LLM."""
        base_url = self.config.get('AI_BASE_URL', '').rstrip('/')
        if not base_url:
            raise ValueError("AI_BASE_URL为空")

        model = self.config.get('AI_MODEL', 'gpt-4o-mini')
        timeout = self.config.get('AI_TIMEOUT', 30)
        api_key = self.config.get('AI_API_KEY', '').strip()

        endpoint = f"{base_url}/chat/completions"

        # System prompt based on rule type
        if rule_type == "detection":
            system_prompt = (
                "你是一个网络安全检测规则生成专家。"
                "根据用户的自然语言描述生成检测规则配置。"
                "返回JSON格式，不要使用markdown代码块。"
                "Schema: {"
                '"name":"规则名称",'
                '"threat_type":"威胁类型",'
                '"description":"规则描述",'
                '"severity":"严重程度(高/中/低)",'
                '"conditions":{'
                '"protocol":"协议",'
                '"port":"端口",'
                '"threshold":"阈值",'
                '"time_window":"时间窗口(秒)"'
                '},'
                '"actions":{'
                '"type":"动作类型(alert/block/limit)",'
                '"parameters":"动作参数"'
                '}'
                "}"
            )
        elif rule_type == "prevention":
            system_prompt = (
                "你是一个网络防御规则生成专家。"
                "根据用户的自然语言描述生成防御规则配置。"
                "返回JSON格式，不要使用markdown代码块。"
                "Schema: {"
                '"name":"规则名称",'
                '"threat_type":"威胁类型",'
                '"description":"规则描述",'
                '"conditions":{'
                '"src_ip":"源IP条件",'
                '"dst_ip":"目标IP条件",'
                '"port":"端口条件",'
                '"protocol":"协议条件"'
                '},'
                '"action":{'
                '"type":"动作类型(block/redirect/throttle)",'
                '"target":"动作目标",'
                '"duration":"持续时间(秒)"'
                '}'
                "}"
            )
        else:  # alert
            system_prompt = (
                "你是一个安全告警规则生成专家。"
                "根据用户的自然语言描述生成告警规则配置。"
                "返回JSON格式，不要使用markdown代码块。"
                "Schema: {"
                '"name":"规则名称",'
                '"severity":"严重程度(高/中/低)",'
                '"description":"规则描述",'
                '"conditions":{'
                '"threat_type":"威胁类型",'
                '"min_severity":"最小严重程度",'
                '"time_range":"时间范围"'
                '},'
                '"notification":{'
                '"method":"通知方式(web/email/sms)",'
                '"recipients":"接收者",'
                '"template":"消息模板"'
                '}'
                "}"
            )

        payload = {
            "model": model,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
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
            raise RuntimeError(f"LLM请求失败: HTTP {resp.status_code} {resp.text}")

        data = resp.json()
        choices = data.get("choices") or []
        if not choices:
            raise RuntimeError("LLM响应为空")

        content = ((choices[0] or {}).get("message") or {}).get("content", "")

        # Clean up markdown if present
        content = content.strip()
        if content.startswith("```json"):
            content = content[7:]
        elif content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]

        content = content.strip()

        # Parse JSON
        try:
            rule = json.loads(content)
        except json.JSONDecodeError:
            # Try to extract JSON from text
            match = re.search(r'\{[\s\S]*\}', content)
            if match:
                rule = json.loads(match.group(0))
            else:
                raise RuntimeError("无法解析LLM返回的JSON")

        # Add metadata
        rule['rule_type'] = rule_type
        rule['generated_by'] = 'ai'
        rule['version'] = '1.0'

        return self._normalize_rule(rule, rule_type)

    def _normalize_rule(
        self,
        rule: Dict[str, Any],
        rule_type: str
    ) -> Dict[str, Any]:
        """Normalize and validate the rule structure."""
        normalized = {
            "name": str(rule.get("name", "AI生成的规则")).strip(),
            "description": str(rule.get("description", "")).strip(),
            "rule_type": rule_type,
            "enabled": True,
            "created_at": None,  # Will be set when saved
        }

        if rule_type == "detection":
            normalized.update({
                "threat_type": str(rule.get("threat_type", "未知威胁")).strip(),
                "severity": str(rule.get("severity", "中")).strip(),
                "conditions": rule.get("conditions", {}),
                "actions": rule.get("actions", {}),
            })

        elif rule_type == "prevention":
            normalized.update({
                "threat_type": str(rule.get("threat_type", "未知威胁")).strip(),
                "conditions": rule.get("conditions", {}),
                "action": rule.get("action", {}),
            })

        else:  # alert
            normalized.update({
                "severity": str(rule.get("severity", "中")).strip(),
                "conditions": rule.get("conditions", {}),
                "notification": rule.get("notification", {}),
            })

        return normalized

    def generate_rule_from_example(
        self,
        example_rules: List[Dict[str, Any]],
        description: str
    ) -> Dict[str, Any]:
        """
        Generate a rule based on examples.

        Args:
            example_rules: List of existing rules to learn from
            description: Description of the new rule

        Returns:
            Generated rule
        """
        # Create context from examples
        context = {
            "examples": example_rules[:3],  # Limit to 3 examples
            "description": description
        }

        return self.generate_rule(
            f"基于以下示例规则生成新规则: {description}\n"
            f"示例: {json.dumps(example_rules[0], ensure_ascii=False)}",
            rule_type="detection"
        )

    def batch_generate_rules(
        self,
        descriptions: List[str],
        rule_type: str = "detection"
    ) -> List[Dict[str, Any]]:
        """
        Generate multiple rules from descriptions.

        Args:
            descriptions: List of rule descriptions
            rule_type: Type of rules to generate

        Returns:
            List of generated rules
        """
        rules = []
        for desc in descriptions:
            try:
                rule = self.generate_rule(desc, rule_type)
                rules.append(rule)
            except Exception as e:
                logger.error(f"生成规则失败 '{desc}': {e}")
                # Add fallback rule
                rules.append({
                    "name": f"规则{len(rules)+1}",
                    "description": desc,
                    "rule_type": rule_type,
                    "error": str(e)
                })

        return rules


# Test the rule generator
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    generator = AIRuleGenerator()

    # Example usage
    rule = generator.generate_rule(
        "检测SSH暴力破解攻击，同一IP在一分钟内连接尝试超过10次",
        rule_type="detection"
    )

    print(f"生成的规则: {json.dumps(rule, indent=2, ensure_ascii=False)}")
