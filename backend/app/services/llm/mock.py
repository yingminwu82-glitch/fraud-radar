import json

from app.services.llm.base import LLMProvider


class MockLLMProvider(LLMProvider):
    """Deterministic local interpretation for demos and frontend development."""
    model_name = "mock-llm"

    async def generate_report(self, context: dict) -> dict:
        assessment=context["risk_assessment"]
        categories=context.get("categories",[])
        ranked=sorted((c for c in categories if c.get("score") is not None),key=lambda c:c.get("contribution") or 0,reverse=True)
        drivers=[f"{c['category'].replace('_',' ').title()} ({c['contribution']:.1f} points)" for c in ranked[:3]]
        agreement=context.get("provider_agreement",[])
        missing=context.get("limitations",[])
        level=assessment["risk_level"]
        overall=f"The Risk Engine assigned {assessment['final_score']:.1f}/100 ({level}). This report explains the supplied evidence and does not make a fraud determination."
        by_category={c["category"]:c for c in categories}
        sections={}
        for key,title in [("ip_reputation","IP reputation"),("network_anonymity","Network anonymity"),("malicious_infrastructure","Malicious infrastructure"),("geographic_risk","Geographic risk"),("transaction_behavior","Transaction behaviour"),("account_characteristics","Account risk")]:
            item=by_category.get(key)
            if not item or item.get("score") is None:
                sections[key]="Unknown / Insufficient Evidence. No usable evidence was supplied for this category."
            else:
                sources=sorted({p for ev in item.get("evidence",[]) for p in ev.get("providers",[])})
                sections[key]=f"The supplied category score is {item['score']}/100 with {item.get('evidence_strength',0):.0%} evidence strength and {item.get('contribution') or 0:.1f} contribution. Evidence sources: {', '.join(sources) if sources else 'transaction context'}."
        positives=[]
        for provider in context.get("provider_results",[]):
            for signal in provider.get("signals",[]):
                if signal.get("risk_score") == 0 and not signal.get("missing"):
                    positives.append(f"{provider['provider']}: {signal['factor']} had no supporting suspicious signal.")
        limitations=list(missing)
        if not any(c.get("category")=="account_characteristics" and c.get("score") is not None for c in categories):
            limitations.append("Insufficient account-level evidence is available.")
        return {
            "executive_summary": overall,
            "overall_interpretation": f"Evidence strength is {assessment['evidence_strength'].lower()}. The highest weighted drivers are {', '.join(drivers) if drivers else 'not available'}. Provider agreement: {'; '.join(agreement) if agreement else 'no cross-provider agreement was supplied'}. Treat missing inputs as unknown, not as evidence of safety.",
            "sections": sections,
            "multi_source_analysis": "; ".join(agreement) if agreement else "No provider agreement was recorded. Each provider's status and supplied signals are shown separately.",
            "risk_contribution_analysis": "Risk contributions are copied from the Risk Engine: " + (", ".join(drivers) if drivers else "no category contributions are available."),
            "user_preference_impact": "Category weights in this report come from the selected Risk Profile. Higher weights give a category more influence in the Risk Engine's personalized score.",
            "positive_signals": positives,
            "limitations": limitations,
            "recommended_actions": self._actions(level),
            "key_risk_drivers": drivers,
            "confidence_explanation": f"Evidence strength is {assessment['evidence_strength']}. This reflects the available Risk Engine evidence and source agreement; it is not a probability of fraud.",
        }

    async def answer(self, context: dict, history: list[dict], question: str) -> str:
        if context.get("context_type")=="provider_evidence":
            provider_rows=context.get("provider_evidence",[])
            provider_summary=[]
            for row in provider_rows:
                fields=row.get("provider_reported_fields") or {}
                signals=row.get("backend_normalized_signals",[])
                field_values=", ".join(f"{key}={json.dumps(value,ensure_ascii=False)}" for key,value in fields.items())
                provider_summary.append(
                    f"{row.get('provider')}: status {row.get('status')}; provider-reported values "
                    f"{field_values or 'Unknown / Insufficient Evidence'}; "
                    f"normalized signals {', '.join(s.get('factor','') for s in signals) if signals else 'none'}."
                )
            mappings=context.get("dimension_mappings",[])
            relevant=[f"{row.get('dimension_name') or row.get('category')} ({row.get('score') if row.get('score') is not None else 'N/A'} score, {row.get('contribution') if row.get('contribution') is not None else 'N/A'} contribution)" for row in mappings if row.get("evidence")]
            return (
                "Provider-reported facts: " + (" ".join(provider_summary) if provider_summary else "Unknown / Insufficient Evidence.") +
                " Backend-normalized signals are separate from provider fields. Risk Engine dimension mappings with evidence: " +
                (", ".join(relevant) if relevant else "none available.") +
                " A contextual field is not evidence that it affected the score unless it appears in the normalized signal and dimension mapping."
            )
        score=context["risk_assessment"]["final_score"]
        level=context["risk_assessment"]["risk_level"]
        cats=sorted((c for c in context.get("categories",[]) if c.get("contribution") is not None),key=lambda c:c["contribution"],reverse=True)
        if not cats: return "There is insufficient category evidence in the current analysis to identify a leading contributor."
        biggest=cats[0]
        return f"The Risk Engine assigned {score:.1f}/100 ({level}). {biggest['category'].replace('_',' ').title()} is the largest supplied contributor at {biggest['contribution']:.1f} points. This is an interpretation of the current analysis, not a new score."

    @staticmethod
    def _actions(level: str) -> list[str]:
        if level in {"High Risk","Critical Risk"}: return ["Require additional authentication before completion.","Route the transaction for manual review.","Verify the transaction context and monitor subsequent activity."]
        if level=="Medium Risk": return ["Request additional verification where appropriate.","Review unusual transaction patterns and monitor follow-up activity."]
        return ["Proceed under normal controls.","Continue standard monitoring."]
