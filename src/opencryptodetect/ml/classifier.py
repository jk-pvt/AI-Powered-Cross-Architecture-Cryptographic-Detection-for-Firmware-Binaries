"""Training and evaluation routines for cryptographic ML classifiers."""

import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from rich.console import Console
from rich.table import Table
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import train_test_split

from opencryptodetect.features.feature_vector import FEATURE_NAMES
from opencryptodetect.ml.model_registry import ModelManifest
from opencryptodetect.utils.hashing import compute_sha256
from opencryptodetect.version import FEATURE_SCHEMA_VERSION, MODEL_VERSION

console = Console()


def load_dataset(dataset_path: Path):
    """Load features and labels from JSON or NPZ dataset."""
    with dataset_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    X = np.array([sample["features"] for sample in data])
    y = np.array([sample["label"] for sample in data])
    groups = [sample.get("implementation_id", sample.get("label")) for sample in data]
    return X, y, groups


def train_classifier(
    dataset_path: Path,
    model_output_path: Path,
    algorithm: str = "rf",
) -> ModelManifest:
    """Train ML model on feature dataset and export artifact with manifest."""
    console.print(f"[bold cyan]Loading dataset from[/bold cyan] {dataset_path}...")
    X, y, groups = load_dataset(dataset_path)

    # Train/test split with stratification
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    console.print(f"Training on {len(X_train)} samples, testing on {len(X_test)} samples...")

    if algorithm == "gb":
        clf = GradientBoostingClassifier(n_estimators=100, max_depth=5, random_state=42)
        algo_name = "GradientBoostingClassifier"
    else:
        clf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
        algo_name = "RandomForestClassifier"

    clf.fit(X_train, y_train)

    # Evaluate
    y_pred = clf.predict(X_test)
    acc = float(np.mean(y_pred == y_test))
    f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

    console.print(f"[bold green]Training complete![/bold green] Accuracy: {acc:.3f}, F1: {f1:.3f}")

    # Save model artifact
    model_output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, model_output_path)
    checksum = compute_sha256(model_output_path)

    manifest = ModelManifest(
        model_version=MODEL_VERSION,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_names=FEATURE_NAMES,
        classes=sorted(list(set(y))),
        algorithm=algo_name,
        training_samples=len(X_train),
        accuracy=acc,
        f1_weighted=f1,
        created_at=datetime.now(timezone.utc).isoformat(),
        checksum_sha256=checksum,
    )

    manifest_path = model_output_path.parent / "manifests" / f"{model_output_path.stem}_manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest.save(manifest_path)

    console.print(f"Saved model to [bold]{model_output_path}[/bold]")
    console.print(f"Saved manifest to [bold]{manifest_path}[/bold]")
    return manifest


def evaluate_classifier(model_path: Path, test_dataset_path: Path) -> None:
    """Evaluate trained model on test dataset and print detailed report."""
    clf = joblib.load(model_path)
    X_test, y_test, _ = load_dataset(test_dataset_path)

    y_pred = clf.predict(X_test)
    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

    table = Table(title="[bold]Model Evaluation Metrics[/bold]")
    table.add_column("Class", style="cyan")
    table.add_column("Precision", justify="right")
    table.add_column("Recall", justify="right")
    table.add_column("F1-Score", justify="right")
    table.add_column("Support", justify="right")

    for cls_name, metrics in report.items():
        if isinstance(metrics, dict):
            table.add_row(
                cls_name,
                f"{metrics['precision']:.2f}",
                f"{metrics['recall']:.2f}",
                f"{metrics['f1-score']:.2f}",
                str(int(metrics['support'])),
            )

    console.print(table)
