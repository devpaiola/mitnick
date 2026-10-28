from pathlib import Path


def test_safe_example_uses_bound_parameter():
    source = Path(__file__).with_name("good.py").read_text(encoding="utf-8")
    assert '"SELECT * FROM users WHERE name = ?"' in source
    assert "(username,)" in source
    assert "f\"SELECT" not in source


if __name__ == "__main__":
    test_safe_example_uses_bound_parameter()
