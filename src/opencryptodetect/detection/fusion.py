"""Evidence fusion engine combining signatures, heuristics, ML, and policies."""


from opencryptodetect.binary.functions import FunctionContext
from opencryptodetect.core.context import AnalysisContext, Finding
from opencryptodetect.detection.confidence import fuse_confidence_scores
from opencryptodetect.detection.policy import get_policy


class EvidenceFusionEngine:
    """Combines evidence from multiple detection mechanisms into unified, explainable findings."""

    def fuse(
        self,
        sig_findings: list[Finding],
        heuristic_scores: dict[int, float],
        heuristic_evidences: dict[int, list[str]],
        ml_predictions: dict[int, dict[str, float]],
        functions_map: dict[int, FunctionContext],
        ctx: AnalysisContext,
    ) -> list[Finding]:
        """Produce fused, deduplicated, explainable findings."""
        fused_findings: list[Finding] = []
        handled_funcs: set = set()

        # Step 1: Process signature findings (highest baseline confidence)
        for sf in sig_findings:
            addr = sf.address
            f_ctx = functions_map.get(addr)
            h_score = heuristic_scores.get(addr, 0.0)
            h_ev = heuristic_evidences.get(addr, [])
            ml_probs = ml_predictions.get(addr, {})

            # Look up ML probability for this detected algorithm
            ml_prob = None
            for cls_name, prob in ml_probs.items():
                if cls_name.lower() in sf.algorithm.lower():
                    ml_prob = prob
                    break

            # Fuse confidence
            final_conf = fuse_confidence_scores(
                sig_confidence=sf.confidence,
                heuristic_score=h_score,
                ml_probability=ml_prob,
            )

            # Combine evidence
            combined_evidence = list(sf.evidence)
            methods = list(sf.detection_methods)

            if h_ev:
                methods.append("heuristic")
                combined_evidence.extend(h_ev[:2])

            if ml_prob is not None and ml_prob > 0.40:
                methods.append("ml")
                combined_evidence.append(f"ML classifier predicted {sf.algorithm} with probability {ml_prob:.2f}")

            # Apply security policy
            policy = get_policy(sf.algorithm)
            status = policy.status if policy else sf.security_status
            note = policy.note if policy else sf.security_note

            # Associate library candidate if detected
            lib_cand = ctx.library_candidates[0].library_name if ctx.library_candidates else None

            fused_findings.append(Finding(
                algorithm=sf.algorithm,
                primitive_type=sf.primitive_type,
                address=sf.address,
                function_name=sf.function_name,
                confidence=final_conf,
                detection_methods=sorted(list(set(methods))),
                evidence=combined_evidence,
                security_status=status,
                security_note=note,
                library_candidate=lib_cand,
            ))
            handled_funcs.add((addr, sf.algorithm.lower()))

        # Step 2: Check ML-only high-confidence predictions (where no signature matched)
        for addr, probs in ml_predictions.items():
            f_ctx = functions_map.get(addr)
            if not f_ctx:
                continue

            for cls_name, prob in probs.items():
                if cls_name in ("NonCrypto", "Unknown"):
                    continue
                if (addr, cls_name.lower()) in handled_funcs:
                    continue

                h_score = heuristic_scores.get(addr, 0.0)
                h_ev = heuristic_evidences.get(addr, [])

                # Emit if ML is confident, and either heuristics support it or heuristics are disabled (ML-only mode)
                if prob >= 0.80 and (h_score >= 0.30 or not heuristic_scores):
                    final_conf = fuse_confidence_scores(
                        sig_confidence=None,
                        heuristic_score=h_score,
                        ml_probability=prob,
                    )
                    evidence = [
                        f"ML function classifier probability {prob:.2f} for {cls_name}",
                    ]
                    evidence.extend(h_ev)

                    policy = get_policy(cls_name)
                    status = policy.status if policy else "secure"
                    note = policy.note if policy else None

                    fused_findings.append(Finding(
                        algorithm=cls_name,
                        primitive_type="cipher" if "AES" in cls_name or "ChaCha" in cls_name else "hash",
                        address=addr,
                        function_name=f_ctx.name,
                        confidence=final_conf,
                        detection_methods=["ml", "heuristic"],
                        evidence=evidence,
                        security_status=status,
                        security_note=note,
                    ))
                    handled_funcs.add((addr, cls_name.lower()))

        return fused_findings
