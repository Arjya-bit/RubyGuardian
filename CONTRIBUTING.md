# Contributing to RubyGuardian

Thank you for your interest in contributing to the RubyGuardian security research framework.

## Code of Conduct

By participating, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the bug report template
3. Include: Ruby/Python version, OS, steps to reproduce, expected vs actual behavior

### Suggesting Enhancements

1. Open a feature request issue
2. Describe the use case and expected behavior
3. Include any relevant MITRE ATT&CK references

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-detection-rule`)
3. Write tests for new functionality
4. Ensure all tests pass (`make test`)
5. Run linters (`make lint`)
6. Submit a pull request with a clear description

## Development Setup

```bash
# Install dependencies
bundle install
pip install -r requirements.txt
npm install --prefix 06_dashboard/web_ui

# Run tests
make test

# Run linters
make lint
```

## Code Style

- **Ruby**: Follow `.rubocop.yml` configuration
- **Python**: Follow `.flake8` and PEP 8
- **JavaScript**: ESLint with Airbnb config

## Security Considerations

- All attack PoCs must use benign payloads (calculator spawn, `id` command)
- Never include real credentials, API keys, or sensitive data
- All network operations must be configurable to localhost/isolated networks
- Document MITRE ATT&CK mappings for all attack techniques
- Include detection signatures for every new attack module

## Module Guidelines

### Adding a New Attack Technique

1. Create a subdirectory under the appropriate attack category
2. Include a `README.md` with theory and ATT&CK mapping
3. Implement the technique with safety guards
4. Write corresponding detection rules in `02_detection_engine/`
5. Add test cases in `09_testing/`

### Adding a New Detection Rule

1. Define the rule in YAML format under `config/signatures/`
2. Implement the rule class in `rule_engine/rules/`
3. Write unit tests and integration tests
4. Document false positive considerations
