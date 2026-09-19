"""CLI commands implementation for OpenCryptoDetect."""

import sys
from pathlib import Path

import click
from rich.console import Console

from opencryptodetect.cli.formatting import render_inspection
from opencryptodetect.core.config import OCDConfig
from opencryptodetect.core.exceptions import OCDError
from opencryptodetect.input.inspector import FileInspector
from opencryptodetect.utils.logging import setup_logging
from opencryptodetect.version import __version__

console = Console()


def handle_error(e: Exception, verbose: bool = False) -> None:
    """Print clean error messages without raw stack traces unless in verbose mode."""
    if isinstance(e, OCDError):
        console.print(f"[bold red]{e}[/bold red]", style="red")
    else:
        console.print(f"[bold red]ERROR [UNEXPECTED]:[/bold red] {e}", style="red")
    if verbose:
        console.print_exception(show_locals=True)
    sys.exit(1)


@click.group()
@click.version_option(version=__version__, prog_name="OpenCryptoDetect")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Open-source cross-architecture cryptographic primitive detection for firmware binaries."""
    ctx.ensure_object(dict)


@cli.command("inspect")
@click.argument("file_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--arch", "-a", help="Override architecture (e.g. arm, aarch64, x86, x86_64, mips, riscv)")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose debug output")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential messages")
def inspect_cmd(file_path: Path, arch: str | None, verbose: bool, quiet: bool) -> None:
    """Inspect binary format, architecture, hashes, and executable metadata."""
    setup_logging(verbose=verbose, quiet=quiet)
    cfg = OCDConfig(arch_override=arch, verbose=verbose, quiet=quiet)
    try:
        inspector = FileInspector(cfg)
        analysis_ctx = inspector.inspect(file_path)
        render_inspection(analysis_ctx)
    except Exception as e:
        handle_error(e, verbose=verbose)


@cli.command("analyze")
@click.argument("file_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--format", "-f", "output_format", type=click.Choice(["terminal", "json", "cbom", "html"]), default="terminal", help="Primary output format")
@click.option("--cbom", is_flag=True, help="Generate CycloneDX CBOM output")
@click.option("--html", is_flag=True, help="Generate standalone HTML report")
@click.option("--json", "json_flag", is_flag=True, help="Generate JSON report")
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Output path for reports")
@click.option("--arch", "-a", help="Override architecture")
@click.option("--stage", type=click.Choice(["inspect", "binary", "crypto", "all"]), default="all", help="Analysis stage cutoff")
@click.option("--no-cache", is_flag=True, help="Bypass analysis cache")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose debug output")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output")
def analyze_cmd(
    file_path: Path,
    output_format: str,
    cbom: bool,
    html: bool,
    json_flag: bool,
    output: Path | None,
    arch: str | None,
    stage: str,
    no_cache: bool,
    verbose: bool,
    quiet: bool,
) -> None:
    """Analyze binary to identify and explain cryptographic primitives."""
    setup_logging(verbose=verbose, quiet=quiet)
    cfg = OCDConfig(
        arch_override=arch,
        output_format=output_format,
        generate_cbom=cbom or (output_format == "cbom"),
        generate_html=html or (output_format == "html"),
        generate_json=json_flag or (output_format == "json"),
        output_path=output,
        stage=stage,
        use_cache=not no_cache,
        verbose=verbose,
        quiet=quiet,
    )
    try:
        from opencryptodetect.core.pipeline import AnalysisPipeline
        pipeline = AnalysisPipeline(cfg)
        pipeline.run(file_path)
    except Exception as e:
        handle_error(e, verbose=verbose)


@cli.command("batch")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--output-dir", "-o", type=click.Path(path_type=Path), default=Path("./ocd_batch_output"), help="Directory to save per-file reports")
@click.option("--arch", "-a", help="Override architecture")
@click.option("--cbom", is_flag=True, help="Generate CBOM for each binary")
@click.option("--html", is_flag=True, help="Generate HTML report for each binary")
@click.option("--verbose", "-v", is_flag=True, help="Verbose logs")
@click.option("--quiet", "-q", is_flag=True, help="Quiet output")
def batch_cmd(directory: Path, output_dir: Path, arch: str | None, cbom: bool, html: bool, verbose: bool, quiet: bool) -> None:
    """Batch analyze multiple binary files in a directory."""
    setup_logging(verbose=verbose, quiet=quiet)
    try:
        from opencryptodetect.core.pipeline import run_batch
        run_batch(
            directory=directory,
            output_dir=output_dir,
            arch=arch,
            cbom=cbom,
            html=html,
            verbose=verbose,
            quiet=quiet,
        )
    except Exception as e:
        handle_error(e, verbose=verbose)


@cli.command("benchmark")
@click.option("--dataset", type=click.Path(path_type=Path), help="Custom dataset path")
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Benchmark results output JSON")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def benchmark_cmd(dataset: Path | None, output: Path | None, verbose: bool) -> None:
    """Run cross-architecture crypto detection benchmark suite."""
    setup_logging(verbose=verbose)
    try:
        from benchmarks.benchmark import run_benchmarks
        run_benchmarks(dataset_dir=dataset, output_file=output)
    except Exception as e:
        handle_error(e, verbose=verbose)


@cli.group("ml")
def ml_group() -> None:
    """Machine learning model preparation, training, evaluation, and export."""


@ml_group.command("prepare-dataset")
@click.option("--output-dir", "-o", type=click.Path(path_type=Path), default=Path("dataset/metadata"), help="Output directory for feature dataset")
@click.option("--samples", "-n", type=int, default=100, help="Number of samples to compile/generate")
def ml_prepare_dataset(output_dir: Path, samples: int) -> None:
    """Generate and extract features from cryptographic and non-cryptographic binaries."""
    try:
        from dataset.generator.generate_corpus import generate_training_dataset
        generate_training_dataset(output_dir=output_dir, num_samples=samples)
    except Exception as e:
        handle_error(e)


@ml_group.command("train")
@click.option("--dataset", "-d", type=click.Path(exists=True, path_type=Path), default=Path("dataset/metadata/features.json"), help="Path to feature dataset")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=Path("models/model_v1.joblib"), help="Path to save trained model")
@click.option("--algorithm", "-a", type=click.Choice(["rf", "gb"]), default="rf", help="ML algorithm (rf=Random Forest, gb=Gradient Boosting)")
def ml_train(dataset: Path, output: Path, algorithm: str) -> None:
    """Train machine learning classifier for cryptographic function detection."""
    try:
        from opencryptodetect.ml.classifier import train_classifier
        train_classifier(dataset_path=dataset, model_output_path=output, algorithm=algorithm)
    except Exception as e:
        handle_error(e)


@ml_group.command("evaluate")
@click.option("--model", "-m", type=click.Path(exists=True, path_type=Path), default=Path("models/model_v1.joblib"), help="Path to trained model")
@click.option("--dataset", "-d", type=click.Path(exists=True, path_type=Path), default=Path("dataset/metadata/features.json"), help="Evaluation dataset")
def ml_evaluate(model: Path, dataset: Path) -> None:
    """Evaluate trained ML model performance metrics."""
    try:
        from opencryptodetect.ml.classifier import evaluate_classifier
        evaluate_classifier(model_path=model, test_dataset_path=dataset)
    except Exception as e:
        handle_error(e)


@ml_group.command("export")
@click.option("--model", "-m", type=click.Path(exists=True, path_type=Path), default=Path("models/model_v1.joblib"), help="Path to model file")
@click.option("--output-dir", "-o", type=click.Path(path_type=Path), default=Path("models"), help="Export directory")
def ml_export(model: Path, output_dir: Path) -> None:
    """Export model bundle with schema manifest, checksum, and metadata."""
    try:
        from opencryptodetect.ml.model_registry import export_model_package
        export_model_package(model_path=model, output_dir=output_dir)
    except Exception as e:
        handle_error(e)
