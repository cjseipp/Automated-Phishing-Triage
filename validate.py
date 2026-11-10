
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phishing_triage.analyzer import analyze_file

LABELS = ROOT / "validation" / "labels.csv"
SAMPLES = ROOT / "samples"

THRESHOLD = 30


def main():
    tp = fp = tn = fn = 0

    with LABELS.open(newline="", encoding="utf-8-sig") as file:
        records = list(csv.DictReader(file))

    print("\nPHASE 1.5 - DETECTION VALIDATION")
    print("-" * 65)

    for record in records:
        filename = record["filename"].strip()
        expected = record["label"].strip().lower()

        if expected not in {"phishing", "legitimate"}:
            raise ValueError(f"Invalid label for {filename}: {expected}")

        sample_path = SAMPLES / filename
        if not sample_path.is_file():
            raise FileNotFoundError(sample_path)

        result = analyze_file(sample_path)
        score = result["risk"]["score"]

        predicted = "phishing" if score >= THRESHOLD else "legitimate"

        if expected == "phishing" and predicted == "phishing":
            tp += 1
        elif expected == "legitimate" and predicted == "phishing":
            fp += 1
        elif expected == "legitimate" and predicted == "legitimate":
            tn += 1
        else:
            fn += 1

        print(
            f"{filename}: "
            f"Expected={expected}, "
            f"Predicted={predicted}, "
            f"Score={score}"
        )

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    specificity = tn / (tn + fp) if tn + fp else 0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0
    )

    print("\nVALIDATION RESULTS")
    print("-" * 65)
    print(f"Threshold: {THRESHOLD}/100")
    print(f"True Positives:  {tp}")
    print(f"False Positives: {fp}")
    print(f"True Negatives:  {tn}")
    print(f"False Negatives: {fn}")
    print(f"Accuracy:        {accuracy:.2%}")
    print(f"Precision:       {precision:.2%}")
    print(f"Recall:          {recall:.2%}")
    print(f"Specificity:     {specificity:.2%}")
    print(f"F1 Score:        {f1:.2%}")


if __name__ == "__main__":
    main()
