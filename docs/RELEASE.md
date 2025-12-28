# Release Checklist

This document describes the release process for the AGIRAILS Python SDK.

## Version Scheme

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking API changes
- **MINOR**: New features, backwards compatible
- **PATCH**: Bug fixes, backwards compatible

Current version: `2.0.0`

---

## Pre-Release Checklist

### 1. Code Quality

- [ ] All tests pass: `python3 -m pytest`
- [ ] Security coverage ≥90%: `python3 -m pytest --cov=agirails.utils.security --cov=agirails.utils.validation`
- [ ] No linting errors: `ruff check src/ tests/`
- [ ] Type checking passes: `mypy src/`

### 2. Documentation

- [ ] README.md is up to date
- [ ] All public APIs have docstrings
- [ ] CHANGELOG.md updated with release notes
- [ ] MIGRATION.md updated if breaking changes

### 3. Version Bump

Update version in two places:

```python
# src/agirails/version.py
__version__ = "2.0.1"  # New version
```

```toml
# pyproject.toml
[project]
version = "2.0.1"  # New version
```

### 4. Parity Check

- [ ] Parity tests pass: `python3 -m pytest tests/test_parity.py`
- [ ] TypeScript SDK version matches (check PARITY_CHECKLIST.md)

---

## Build Process

### 1. Clean Previous Builds

```bash
rm -rf dist/ build/ *.egg-info
```

### 2. Build Package

```bash
python3 -m build
```

This creates:
- `dist/agirails-X.Y.Z-py3-none-any.whl` (wheel)
- `dist/agirails-X.Y.Z.tar.gz` (source distribution)

### 3. Verify Package

```bash
twine check dist/*
```

### 4. Test Installation (Optional)

```bash
pip install dist/agirails-*.whl
python3 -c "import agirails; print(agirails.__version__)"
pip uninstall agirails -y
```

---

## Publishing

### Test PyPI (Staging)

First, test on Test PyPI:

```bash
twine upload --repository testpypi dist/*
```

Verify installation from Test PyPI:

```bash
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ agirails
```

### Production PyPI

Once verified, publish to production:

```bash
twine upload dist/*
```

---

## Post-Release

### 1. Git Tag

```bash
git tag -a v2.0.1 -m "Release v2.0.1"
git push origin v2.0.1
```

### 2. GitHub Release

1. Go to GitHub Releases
2. Create new release from tag
3. Copy changelog entries as release notes
4. Attach wheel and sdist files

### 3. Announce

- [ ] Update Discord #announcements
- [ ] Tweet from @agirails (if applicable)
- [ ] Update documentation site

---

## Hotfix Process

For critical security fixes:

1. Create hotfix branch: `git checkout -b hotfix/2.0.2`
2. Fix issue with minimal changes
3. Bump PATCH version
4. Run full test suite
5. Fast-track release (skip Test PyPI if urgent)
6. Merge back to main

---

## Rollback

If a release has critical issues:

1. Yank the bad release: `pip index versions agirails` then contact PyPI support
2. Publish fixed version with incremented PATCH
3. Communicate issue to users

---

## Environment Variables

Required for publishing:

| Variable | Description |
|----------|-------------|
| `TWINE_USERNAME` | PyPI username (or `__token__` for API token) |
| `TWINE_PASSWORD` | PyPI password or API token |

---

## Contacts

- **Release Manager**: team@agirails.io
- **Security Issues**: security@agirails.io
