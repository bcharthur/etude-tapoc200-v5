from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
src = (ROOT / "v5patchlab" / "otaexact.py").read_text(
    encoding="utf-8"
).lower()

def main():
    assert "for timestamp in" not in src
    assert "itertools.product" not in src
    assert "random.randint" not in src
    assert "nextcontinuationtoken" in src
    assert "continuation not followed" in src
    print("otaexact boundedness self-test: OK")

if __name__ == "__main__":
    main()
