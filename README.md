# Gemini Code Security Review

AI-powered security review GitHub Action using **Gemini CLI** to analyze code changes for security vulnerabilities.

This is a community port of [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review) adapted for Google Gemini CLI.

## Features

- **AI-Powered Analysis** — Uses Gemini's advanced reasoning for semantic security understanding
- **Diff-Aware Scanning** — Only analyzes changed files in PRs
- **PR Comments** — Auto-comments on PRs with security findings
- **Language Agnostic** — Works with any programming language
- **False Positive Filtering** — Hard-coded exclusion rules to reduce noise
- **Gemini CLI Integration** — `/security-review` slash command for local use

## Quick Start

```yaml
name: Security Review

permissions:
  pull-requests: write
  contents: read

on:
  pull_request:

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
          fetch-depth: 2

      - uses: your-org/gemini-code-security-review@main
        with:
          gemini-api-key: ${{ secrets.GEMINI_API_KEY }}
          comment-pr: true
```

## Configuration

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `gemini-api-key` | Google Gemini API key | — | Gemini only |
| `comment-pr` | Comment on PRs with findings | `true` | No |
| `upload-results` | Upload results as artifacts | `true` | No |
| `gemini-model` | Gemini model to use | `gemini-2.5-pro` | No |
| `geminicli-timeout` | Analysis timeout (minutes) | `20` | No |
| `exclude-directories` | Comma-separated dirs to exclude | — | No |
| `run-every-commit` | Run on every commit (skip cache) | `false` | No |
| `custom-security-scan-instructions` | Path to custom scan instructions file | — | No |
| `llm-provider` | LLM provider: `gemini`, `ollama`, `lmstudio` | `gemini` | No |
| `local-llm-model` | Local model name (e.g. `llama3.2`, `qwen2.5-coder`) | `llama3.2` | No |
| `local-llm-base-url` | Override local LLM server URL | *(provider default)* | No |

## Using a Local LLM (Ollama / LM Studio)

API 키 없이 로컬에서 실행할 수 있습니다.

### Ollama

```bash
# 1. Ollama 설치 및 모델 다운로드
ollama pull llama3.2          # 경량
ollama pull qwen2.5-coder     # 코드 특화 (권장)
ollama pull deepseek-r1:8b    # 추론 강화

# 2. 로컬에서 보안 리뷰 실행
LLM_PROVIDER=ollama LOCAL_LLM_MODEL=qwen2.5-coder \
  GITHUB_TOKEN=... GITHUB_REPOSITORY=owner/repo PR_NUMBER=42 \
  python geminicli/github_action_audit.py
```

### GitHub Actions에서 Ollama 사용

Self-hosted runner에 Ollama를 설치한 경우:

```yaml
- uses: your-org/gemini-code-security-review@main
  with:
    llm-provider: ollama
    local-llm-model: qwen2.5-coder
    local-llm-base-url: http://localhost:11434
    comment-pr: true
```

### LM Studio

```yaml
- uses: your-org/gemini-code-security-review@main
  with:
    llm-provider: lmstudio
    local-llm-model: your-loaded-model-name
    comment-pr: true
```

### 권장 로컬 모델

| 용도 | 모델 | 크기 |
|------|------|------|
| 코드 보안 분석 (최고) | `qwen2.5-coder:32b` | 20GB |
| 코드 보안 분석 (균형) | `qwen2.5-coder:7b` | 4.7GB |
| 경량 / 빠른 분석 | `llama3.2:3b` | 2GB |
| 추론 강화 | `deepseek-r1:8b` | 5GB |

## Local Usage (Gemini CLI Slash Command)

With [Gemini CLI](https://github.com/google-gemini/gemini-cli) installed:

```bash
# From any git repository
gemini /security-review
```

This runs a security review of all pending branch changes using the `.gemini/commands/security-review.toml` command.

## Setup

### 1. Get a Gemini API Key

Get a free API key at [Google AI Studio](https://aistudio.google.com/apikey).

### 2. Add the Secret to Your Repository

```
Settings → Secrets and variables → Actions → New repository secret
Name: GEMINI_API_KEY
Value: your-api-key
```

### 3. Add the Workflow

Copy `.github/workflows/example-security-review.yml` to your repository.

## Differences from Claude Code Version

| Feature | Claude Code Version | Gemini CLI Version |
|---------|--------------------|--------------------|
| AI Engine | Claude (Anthropic) | Gemini (Google) |
| CLI Tool | `claude` | `gemini` |
| API Key | `ANTHROPIC_API_KEY` | `GEMINI_API_KEY` |
| Default Model | `claude-opus-4-1` | `gemini-2.5-pro` |
| Slash Command | `.claude/commands/*.md` | `.gemini/commands/*.toml` |
| FP Filtering | Hard rules + Claude API | Hard rules only |
| Package | `anthropic` | `requests` only |

## Security Note

Not hardened against prompt injection attacks — should only review **trusted PRs**.
Configure GitHub repository to require approval for external contributors before workflow runs.

## License

MIT
