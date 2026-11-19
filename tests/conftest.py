import subprocess, pathlib, pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def root():
    return ROOT


@pytest.fixture(scope="session")
def build(root):
    subprocess.run(["make", "-C", str(root)], check=True, capture_output=True)
    return root / "build"
