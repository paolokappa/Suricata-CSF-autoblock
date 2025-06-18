# Contributing to Suricata-CSF Auto-Block

Thank you for your interest in contributing to this project!

## How to Contribute

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Commit your changes** (`git commit -m 'Add amazing feature'`)
4. **Push to the branch** (`git push origin feature/amazing-feature`)
5. **Open a Pull Request**

## Guidelines

### Code Style
- Use 4 spaces for indentation in Python
- Use 2 spaces for indentation in Bash scripts
- Add comments for complex logic
- Keep functions small and focused

### Commit Messages
- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less

### Testing
- Test your changes on Ubuntu 22.04 and/or 24.04
- Ensure Suricata doesn't generate errors with your changes
- Test both standard and speedtest editions if modifying blockers

### Documentation
- Update README.md if adding new features
- Update CHANGELOG.md for significant changes
- Add comments to your code
- Update help text in scripts

## Reporting Issues

- Use GitHub Issues
- Include your OS version
- Include Suricata version (`suricata --version`)
- Include relevant log snippets
- Describe steps to reproduce

## Feature Requests

- Open an issue with "Feature Request" in the title
- Describe the use case
- Explain why it would be useful for others

## Questions?

Open an issue with "Question" in the title.
