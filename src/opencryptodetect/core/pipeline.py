"""Execution pipeline orchestrating analysis stages."""

import time
from pathlib import Path

from opencryptodetect.architecture.architectures import normalize_arch_string
from opencryptodetect.binary.analyzer import ElfCapstoneAnalyzer
from opencryptodetect.cli.formatting import render_analysis, render_inspection
from opencryptodetect.core.config import OCDConfig
from opencryptodetect.core.context import AnalysisContext
from opencryptodetect.input.inspector import FileInspector
from opencryptodetect.utils.caching import AnalysisCache
from opencryptodetect.utils.logging import get_logger

logger = get_logger()


class AnalysisPipeline:
    """End-to-end analysis orchestrator."""

    def __init__(self, config: OCDConfig | None = None):
        self.config = config or OCDConfig()
        self.inspector = FileInspector(self.config)
        self.cache = AnalysisCache(
            cache_dir=self.config.cache_dir,
            enabled=self.config.use_cache,
        )

    def run(self, file_path: Path) -> AnalysisContext:
        """Run configured analysis stages on target binary."""
        path = Path(file_path).resolve()
        logger.debug(f"Starting pipeline analysis on {path}")

        # Stage 1: Inspect
        t0 = time.time()
        ctx = self.inspector.inspect(path)
        ctx.timing.extraction_seconds = time.time() - t0

        if self.config.stage == "inspect":
            ctx.finish_timing()
            render_inspection(ctx)
            return ctx

        # Check Cache
        cached_result = self.cache.get(ctx.file_sha256)
        if cached_result and self.config.stage == "all" and not (self.config.generate_html or self.config.generate_cbom):
            logger.info("Using cached analysis results.")
            # Note: in later phases, cached results can be deserialized to findings

        # Stage 2: Binary Analysis
        t1 = time.time()
        arch_enum = normalize_arch_string(ctx.architecture)
        analyzer = ElfCapstoneAnalyzer(arch=arch_enum, bitness=ctx.bitness, endianness=ctx.endianness)
        ctx.functions = analyzer.analyze(ctx)
        ctx.timing.binary_analysis_seconds = time.time() - t1
        logger.debug(f"Recovered {len(ctx.functions)} functions from binary")

        if self.config.stage == "binary":
            ctx.finish_timing()
            render_analysis(ctx)
            return ctx

        # Stage 3: Feature Extraction, Crypto Detection & Fusion
        t2 = time.time()
        try:
            from opencryptodetect.detection.detector import CryptoDetectorEngine
            detector = CryptoDetectorEngine(self.config)
            detector.detect(ctx)
        except ImportError:
            # When detection engine is not yet invoked or in transition
            pass
        ctx.timing.fusion_seconds = time.time() - t2

        # Stage 4: Reporting
        t3 = time.time()
        json_path_str: str | None = None
        cbom_path_str: str | None = None
        html_path_str: str | None = None

        if self.config.generate_json:
            try:
                from opencryptodetect.reporting.json_report import generate_json_report
                out = self.config.output_path or path.with_suffix(".ocd.json")
                generate_json_report(ctx, out)
                json_path_str = str(out)
            except Exception as e:
                logger.error(f"Failed to generate JSON report: {e}")

        if self.config.generate_cbom:
            try:
                from opencryptodetect.cbom.generator import generate_cbom_report
                out = self.config.output_path or path.with_suffix(".cbom.json")
                generate_cbom_report(ctx, out)
                cbom_path_str = str(out)
            except Exception as e:
                logger.error(f"Failed to generate CBOM report: {e}")

        if self.config.generate_html:
            try:
                from opencryptodetect.reporting.html_report import generate_html_report
                out = self.config.output_path or path.with_suffix(".ocd.html")
                generate_html_report(ctx, out)
                html_path_str = str(out)
            except Exception as e:
                logger.error(f"Failed to generate HTML report: {e}")

        ctx.timing.reporting_seconds = time.time() - t3
        ctx.finish_timing()

        # Terminal output
        if self.config.output_format == "terminal":
            render_analysis(
                ctx,
                json_path=json_path_str,
                cbom_path=cbom_path_str,
                html_path=html_path_str,
            )

        return ctx


def run_batch(
    directory: Path,
    output_dir: Path,
    arch: str | None = None,
    cbom: bool = False,
    html: bool = False,
    verbose: bool = False,
    quiet: bool = False,
) -> None:
    """Execute batch analysis on directory of binaries."""
    output_dir.mkdir(parents=True, exist_ok=True)
    cfg = OCDConfig(
        arch_override=arch,
        generate_cbom=cbom,
        generate_html=html,
        generate_json=True,
        verbose=verbose,
        quiet=quiet,
    )
    pipeline = AnalysisPipeline(cfg)

    files = [p for p in directory.rglob("*") if p.is_file() and not p.name.endswith((".json", ".html", ".md"))]
    logger.info(f"Discovered {len(files)} files for batch analysis")

    for f in files:
        try:
            logger.info(f"Analyzing {f.name}...")
            cfg.output_path = output_dir / f"{f.name}.ocd.json"
            pipeline.run(f)
        except Exception as e:
            logger.error(f"Batch item failed on {f.name}: {e}")
            continue
