# Contributing to W.A.D.U.H. Scanner

First off, thank you for considering contributing to W.A.D.U.H.! 🎉

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment.

## How Can I Contribute?

### 🐛 Reporting Bugs

Before creating a bug report:
- Check existing issues to avoid duplicates
- Ensure you're using the latest version

When creating a bug report, include:
- Python version (`python --version`)
- Operating system and version
- Complete error message/traceback
- Steps to reproduce the issue
- Expected vs actual behavior

### 💡 Suggesting Features

Feature requests are welcome! Please include:
- Clear description of the feature
- Use case / problem it solves
- Potential implementation approach (optional)

### 🔧 Pull Requests

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Make** your changes
4. **Test** thoroughly
5. **Commit** with clear messages (`git commit -m 'Add amazing feature'`)
6. **Push** to your fork (`git push origin feature/amazing-feature`)
7. **Open** a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/Waduh.git
cd Waduh

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt  # if available

# Run the scanner
python waduh_v3.py --help
```

## Coding Standards

### Python Style
- Follow **PEP 8** guidelines
- Use **type hints** for function signatures
- Maximum line length: **100 characters**
- Use meaningful variable names

### Documentation
- Add docstrings to all public methods
- Update README.md for new features
- Comment complex logic

### Commits
- Use clear, descriptive commit messages
- One logical change per commit
- Reference issue numbers when applicable

## Testing

Before submitting:

```bash
# Syntax check
python -m py_compile waduh_v3.py

# Basic functionality test
python waduh_v3.py --help
```

## Security Considerations

When contributing security-related code:
- Never include actual exploit payloads that could cause harm
- Test payloads should be detection-only, not exploitation
- Follow responsible disclosure for any vulnerabilities found

## Need Help?

- Open an issue with your question
- Tag it with `question` label
- We'll respond as soon as possible

---

Thank you for helping make W.A.D.U.H. better! 💀🔒
