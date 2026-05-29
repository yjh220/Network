#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI Planner - Natural Language to Detection Plan

Converts natural language descriptions into structured threat detection plans.
Similar to FullScopeTest's AI Planner but adapted for network security.

Example:
Input: "帮我创建一个检测计划，监控端口扫描攻击，当检测到异常时发送告警"
Output: Structured plan with detection rules, alert settings, and response actions
"""

import json
import logging
import re
import requests
from datetime import datetime
from typing import Dict, Any, List, Optional

from .config import get_ai_config

logger = logging.getLogger(__name__)

# Allowed operation types for detection planning
ALLOWED_OPERATION_TYPES = {
    "create_detection_rule",
    "update_detection_rule",
    "create_alert_rule",
    "set_monitoring_mode",
    "configure_response_action",
    "analyze_traffic_pattern",
    "schedule_scan",
}


class AIPlanner:
    """
    AI Planner for threat detection planning.

    Converts natural language into structured detection operations.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize AI Planner.

        Args:
            config: Optional AI configuration
        """
        self.config = config or get_ai_config()

    def generate_plan(
        self,
        prompt: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate a detection plan from natural language.

        Args:
            prompt: Natural language description
            context: Additional context (current rules, network config, etc.)

        Returns:
            Structured plan with operations
        """
        text = (prompt or "").strip()
        if not text:
            raise ValueError("prompt不能为空")

        if not self.config.get('AI_ENABLED', True):
            raise ValueError("AI功能未启用")

        api_key = self.config.get('AI_API_KEY', '').strip()
        if api_key:
            try:
                return self._generate_via_llm(text, context or {})
            except Exception as exc:
                logger.warning(f"LLM规划失败，使用fallback: {exc}")

        return self._generate_fallback_plan(text, context or {})

    def _generate_via_llm(
        self,
        prompt: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate plan using LLM."""
        base_url = self.config.get('AI_BASE_URL', '').rstrip('/')
        if not base_url:
            raise ValueError("AI_BASE_URL为空")

        model = self.config.get('AI_MODEL', 'gpt-4o-mini')
        timeout = self.config.get('AI_TIMEOUT', 30)
        api_key = self.config.get('AI_API_KEY', '').strip()

        endpoint = f"{base_url}/chat/completions"

        system_prompt = (
            "你是一个网络安全检测规划助手。"
            "返回单个JSON对象，不要使用markdown。"
            "Schema: "
            "{"
            '"summary":"string (用中文简要描述你计划执行的操作)",'
            '"operations":[{"type":"...", "params":{...}}]'
            "}. "
            "Allowed operation types: create_detection_rule, update_detection_rule, "
            "create_alert_rule, set_monitoring_mode, configure_response_action, "
            "analyze_traffic_pattern, schedule_scan. "
            "对于create_detection_rule，至少包含name, threat_type, detection_criteria。"
            "对于create_alert_rule，至少包含name, severity, notification_method。"
            "重要: summary字段必须使用中文。"
            "关键要求:\n"
            "1. 不要返回markdown代码块，响应必须能被json.loads()解析。\n"
            "2. 只使用有效的JSON语法。"
        )

        user_payload = {
            "prompt": prompt,
            "context": context,
        }

        payload = {
            "model": model,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
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
        choices = data.get("choices") or []
        if not choices:
            raise RuntimeError("LLM响应为空")

        content = ((choices[0] or {}).get("message") or {}).get("content", "")
        raw_plan = self._parse_json_content(content)

        if not isinstance(raw_plan, dict):
            raise RuntimeError("LLM计划不是JSON对象")

        normalized = self._normalize_plan(raw_plan, context)
        normalized["source"] = "llm"
        return normalized

    def _parse_json_content(self, content: Any) -> Any:
        """Parse JSON from LLM response."""
        if isinstance(content, dict):
            return content

        text = str(content or "").strip()
        if not text:
            return {}

        # Try direct JSON
        try:
            return json.loads(text)
        except Exception:
            pass

        # Remove markdown fences
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
        try:
            return json.loads(text)
        except Exception:
            pass

        # Find first JSON object
        match = re.search(r"\{[\s\S]*\}", text)
        if match:
            try:
                return json.loads(match.group(0))
            except Exception:
                return {}
        return {}

    def _normalize_plan(
        self,
        raw_plan: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Normalize the plan structure."""
        operations = raw_plan.get("operations") or []
        normalized_ops = []

        if isinstance(operations, list):
            for op in operations:
                normalized = self._normalize_operation(op, context)
                if normalized:
                    normalized_ops.append(normalized)

        summary = str(raw_plan.get("summary") or "").strip()
        if not summary:
            summary = "AI生成的检测计划"

        return {
            "summary": summary[:300],
            "operations": normalized_ops,
        }

    def _normalize_operation(
        self,
        op: Any,
        context: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Normalize a single operation."""
        if not isinstance(op, dict):
            return None

        op_type = str(op.get("type") or "").strip()
        if op_type not in ALLOWED_OPERATION_TYPES:
            return None

        if op_type == "create_detection_rule":
            return {
                "type": op_type,
                "name": str(op.get("name") or self._default_name("检测规则")).strip(),
                "threat_type": str(op.get("threat_type") or "未知威胁").strip(),
                "detection_criteria": op.get("detection_criteria") or {},
                "severity": str(op.get("severity") or "中").strip(),
                "enabled": op.get("enabled", True),
                "description": str(op.get("description") or "").strip(),
            }

        if op_type == "update_detection_rule":
            return {
                "type": op_type,
                "rule_id": op.get("rule_id"),
                "name": str(op.get("name") or "").strip(),
                "threat_type": str(op.get("threat_type") or "").strip(),
                "detection_criteria": op.get("detection_criteria") or {},
                "severity": str(op.get("severity") or "").strip(),
                "enabled": op.get("enabled", True),
            }

        if op_type == "create_alert_rule":
            return {
                "type": op_type,
                "name": str(op.get("name") or self._default_name("告警规则")).strip(),
                "severity": str(op.get("severity") or "中").strip(),
                "notification_method": str(op.get("notification_method") or "web").strip(),
                "conditions": op.get("conditions") or [],
                "description": str(op.get("description") or "").strip(),
            }

        if op_type == "set_monitoring_mode":
            mode = str(op.get("mode") or "passive").strip()
            if mode not in ["passive", "active", "learning"]:
                mode = "passive"
            return {
                "type": op_type,
                "mode": mode,
                "reason": str(op.get("reason") or "").strip(),
            }

        if op_type == "configure_response_action":
            return {
                "type": op_type,
                "action": str(op.get("action") or "block_ip").strip(),
                "target": str(op.get("target") or "").strip(),
                "duration": int(op.get("duration") or 3600),
                "conditions": op.get("conditions") or [],
            }

        if op_type == "analyze_traffic_pattern":
            return {
                "type": op_type,
                "target": str(op.get("target") or "all").strip(),
                "timeframe": str(op.get("timeframe") or "hour").strip(),
                "analysis_type": str(op.get("analysis_type") or "anomaly").strip(),
            }

        if op_type == "schedule_scan":
            return {
                "type": op_type,
                "scan_type": str(op.get("scan_type") or "vulnerability").strip(),
                "target": str(op.get("target") or "all").strip(),
                "schedule": str(op.get("schedule") or "manual").strip(),
            }

        return None

    def _generate_fallback_plan(
        self,
        prompt: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate a fallback plan when LLM is unavailable."""
        text = prompt.lower()

        operations = []

        # Simple keyword matching for fallback
        if any(k in text for k in ["端口扫描", "port scan", "scan"]):
            operations.append({
                "type": "create_detection_rule",
                "name": self._default_name("端口扫描检测"),
                "threat_type": "端口扫描",
                "detection_criteria": {
                    "threshold": 10,
                    "time_window": 60
                },
                "severity": "中",
                "enabled": True,
                "description": "检测端口扫描攻击"
            })

        if any(k in text for k in ["ddos", "洪水", "flood"]):
            operations.append({
                "type": "create_detection_rule",
                "name": self._default_name("DDoS攻击检测"),
                "threat_type": "DDoS攻击",
                "detection_criteria": {
                    "connection_threshold": 100,
                    "time_window": 10
                },
                "severity": "高",
                "enabled": True,
                "description": "检测DDoS攻击"
            })

        if any(k in text for k in ["告警", "alert", "通知"]):
            operations.append({
                "type": "create_alert_rule",
                "name": self._default_name("安全告警"),
                "severity": "中",
                "notification_method": "web",
                "conditions": [{"threat_detected": True}],
                "description": "检测到威胁时发送告警"
            })

        if not operations:
            operations.append({
                "type": "create_detection_rule",
                "name": self._default_name("通用威胁检测"),
                "threat_type": "未知威胁",
                "detection_criteria": {},
                "severity": "中",
                "enabled": True,
                "description": "AI生成的通用检测规则"
            })

        return {
            "summary": "使用fallback生成的检测计划（LLM不可用）",
            "operations": operations,
            "source": "fallback",
        }

    def _default_name(self, prefix: str) -> str:
        """Generate a default name with timestamp."""
        ts = datetime.now().strftime("%m%d-%H%M%S")
        return f"{prefix} {ts}"


# Test the planner
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    planner = AIPlanner()

    # Example usage
    plan = planner.generate_plan(
        "创建一个检测规则来监控端口扫描攻击，当检测到异常时发送告警"
    )

    print(f"计划摘要: {plan['summary']}")
    print(f"操作:")
    for op in plan['operations']:
        print(f"  - {op['type']}: {op.get('name', 'N/A')}")
