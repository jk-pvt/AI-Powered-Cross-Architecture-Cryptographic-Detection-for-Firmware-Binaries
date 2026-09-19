"""Cryptographic library fingerprinting engine."""


from opencryptodetect.core.context import AnalysisContext, LibraryCandidate
from opencryptodetect.libraries.database import LIBRARY_SIGNATURES


class LibraryFingerprinter:
    """Identifies likely cryptographic libraries present in binary images."""

    def fingerprint(self, ctx: AnalysisContext) -> list[LibraryCandidate]:
        """Examine symbols and extracted strings against library signatures."""
        candidates: list[LibraryCandidate] = []
        all_strings = " ".join(ctx.extracted_strings)
        all_func_names = [f.name for f in ctx.functions]

        for lib_sig in LIBRARY_SIGNATURES:
            evidence: list[str] = []
            score = 0.0

            # Check string occurrences
            matched_strings = [pat for pat in lib_sig.string_patterns if pat in all_strings]
            if matched_strings:
                score += min(0.50, len(matched_strings) * 0.20)
                evidence.append(f"Matched library string patterns: {', '.join(matched_strings)}")

            # Check function symbol prefixes
            matched_symbols = []
            for prefix in lib_sig.function_symbol_prefixes:
                matches = [fn for fn in all_func_names if fn.startswith(prefix)]
                if matches:
                    matched_symbols.extend(matches[:3])

            if matched_symbols:
                score += min(0.45, len(matched_symbols) * 0.15)
                evidence.append(f"Identified library API function symbols: {', '.join(matched_symbols)}")

            if score >= 0.35:
                candidates.append(
                    LibraryCandidate(
                        library_name=lib_sig.name,
                        confidence=min(0.95, round(score, 2)),
                        evidence=evidence,
                    )
                )

        return candidates
