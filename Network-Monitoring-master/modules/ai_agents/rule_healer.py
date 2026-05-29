#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI Rule Healer - Automatic Rule Error Fixing

Analyzes failed detection rules and provides automatic fixes.
Similar to FullScopeTest's AI Script Healer but for security rules.

Example:
Input: Failed rule with error message
Output: Fixed rule with explanation of the problem and solution
"""

import json
import logging
import os
import re
import requests
from typing import Dict, Any, List, Optional

from .config import get_ai_config

logger = logging.getLogger(__name__)


class AIRuleHealer:
    """
    AI Rule Healer for fixing detection rule errors.

    Analyzes failed rules and provides automatic fixes.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize AI Rule Healer.

        Args:
            config: Optional AI configuration
        """
        self.config = config or get_ai_config()

    def diagnose_and_fix(
        self,
        rule: Dict[str, Any],
        error_message: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Diagnose and fix a failed rule.

        Args:
            rule: The failed rule configuration
            error_message: Error message from rule execution
            context: Additional context (logs, network state, etc.)

        Returns:
            Diagnosis with fixed rule and explanation
        """
        if not self.config.get('AI_ENABLED', True):
            raise ValueError("AI功能未启用")

        api_key = self.config.get('AI_API_KEY', '').strip()
        if not api_key:
            raise ValueError("AI_API_KEY未配置")

        try:
            return self._diagnose_via_llm(rule, error_message, context or {})
        except Exception as exc:
            logger.error(f"AI诊断失败: {exc}")
            raise RuntimeError(f"诊断失败: {str(exc)}")

    def _diagnose_via_llm(
        self,
        rule: Dict[str, Any],
        error_message: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Diagnose using LLM."""
        base_url = self.config.get('AI_BASE_URL', '').rstrip('/')
        if not base_url:
            raise ValueError("AI_BASE_URL为空")

        model = self.config.get('AI_MODEL', 'gpt-4o-mini')
        timeout = self.config.get('AI_TIMEOUT', 30)
        api_key = self.config.get('AI_API_KEY', '').strip()

        endpoint = f"{base_url}/chat/completions"

        system_prompt = (
            "你是一个网络安全规则诊断专家。"
            "分析失败的检测规则，找出问题并提供修复建议。"
            "返回JSON格式，不要使用markdown代码块。"
            "Schema: {"
            '"diagnosis":"问题诊断（中文）",'
            '"root_cause":"根本原因（中文）",'
            '"can_auto_fix":"是否可以自动修复(true/false)",'
            '"fixed_rule":"修复后的规则(如果可修复)",'
            '"explanation":"修复说明（中文）",'
            '"verification_steps":["验证步骤1", "验证步骤2"]'
            "}"
        )

        user_prompt = json.dumps({
            "rule": rule,
            "error": error_message,
            "context": context
        }, ensure_ascii=False, indent=2)

        payload = {
            "model": model,
            "temperature": 0.2,
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
            result = json.loads(content)
        except json.JSONDecodeError:
            # Try to extract JSON from text
            match = re.search(r'\{[\s\S]*\}', content)
            if match:
                result = json.loads(match.group(0))
            else:
                raise RuntimeError("无法解析LLM返回的JSON")

        return self._normalize_diagnosis(result, rule)

    def _normalize_diagnosis(
        self,
        diagnosis: Dict[str, Any],
        original_rule: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Normalize the diagnosis structure."""
        return {
            "original_rule": original_rule,
            "diagnosis": str(diagnosis.get("diagnosis", "无法诊断")).strip(),
            "root_cause": str(diagnosis.get("root_cause", "未知")).strip(),
            "can_auto_fix": bool(diagnosis.get("can_auto_fix", False)),
            "fixed_rule": diagnosis.get("fixed_rule", {}),
            "explanation": str(diagnosis.get("explanation", "")).strip(),
            "verification_steps": diagnosis.get("verification_steps", []),
        }

    def analyze_error_pattern(
        self,
        errors: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze patterns in multiple rule errors.

        Args:
            errors: List of error records with rule and error message

        Returns:
            Pattern analysis with recommendations
        """
        if not self.config.get('AI_ENABLED', True):
            return self._fallback_pattern_analysis(errors)

        try:
            return self._analyze_patterns_via_llm(errors)
        except Exception as exc:
            logger.warning(f"LLM模式分析失败，使用fallback: {exc}")
            return self._fallback_pattern_analysis(errors)

    def _analyze_patterns_via_llm(
        self,
        errors: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Analyze error patterns using LLM."""
        base_url = self.config.get('AI_BASE_URL', '').rstrip('/')
        model = self.config.get('AI_MODEL', 'gpt-4o-mini')
        api_key = self.config.get('AI_API_KEY', '').strip()

        endpoint = f"{base_url}/chat/completions"

        system_prompt = (
            "你是一个网络安全规则分析专家。"
            "分析多个规则错误，找出共性问题并提供改进建议。"
            "返回JSON格式，不要使用markdown代码块。"
            "Schema: {"
            '"patterns":["识别的模式1", "模式2"],'
            '"common_causes":["共同原因1", "原因2"],'
            '"recommendations":["改进建议1", "建议2"],'
            '"priority_actions":["优先处理事项"]'
            "}"
        )

        # Summarize errors
        error_summary = "\n".join([
            f"- {e.get('error', 'Unknown error')}"
            for e in errors[:10]  # Limit to 10
        ])

        payload = {
            "model": model,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"分析以下错误:\n{error_summary}"},
            ],
        }

        resp = requests.post(
            endpoint,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=30,
        )

        if resp.status_code >= 400:
            raise RuntimeError(f"LLM请求失败: HTTP {resp.status_code}")

        data = resp.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")

        # Parse JSON
        try:
            result = json.loads(content)
        except json.JSONDecodeError:
            match = re.search(r'\{[\s\S]*\}', content)
            result = json.loads(match.group(0)) if match else {}

        return {
            "total_errors": len(errors),
            "patterns": result.get("patterns", []),
            "common_causes": result.get("common_causes", []),
            "recommendations": result.get("recommendations", []),
            "priority_actions": result.get("priority_actions", []),
        }

    def _fallback_pattern_analysis(
        self,
        errors: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Fallback pattern analysis without LLM."""
        # Simple pattern matching
        error_types = {}
        for e in errors:
            error = e.get("error", "")
            if "timeout" in error.lower():
                error_types["timeout"] = error_types.get("timeout", 0) + 1
            elif "syntax" in error.lower() or "parse" in error.lower():
                error_types["syntax"] = error_types.get("syntax", 0) + 1
            elif "permission" in error.lower() or "access" in error.lower():
                error_types["permission"] = error_types.get("permission", 0) + 1

        return {
            "total_errors": len(errors),
            "patterns": list(error_types.keys()),
            "common_causes": [f"{k}错误出现{v}次" for k, v in error_types.items()],
            "recommendations": ["检查规则语法", "验证网络连接", "确认权限设置"],
            "priority_actions": [],
        }


# Test the rule healer
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    healer = AIRuleHealer()

    # Example usage
    result = healer.diagnose_and_fix(
        rule={
            "name": "SSH暴力破解检测",
            "conditions": {
                "port": 22,
                "threshold": "invalid"
            }
        },
        error_message="Invalid threshold value: 'invalid' must be a number"
    )

    print(f"诊断结果: {result['diagnosis']}")
    print(f"根本原因: {result['root_cause']}")
    print(f"可自动修复: {result['can_auto_fix']}")
