"""
AuditLens — CI/CD Template Generator

Genera archivos de configuración listos para integrar AuditLens
en los pipelines de CI/CD más populares.
"""
from __future__ import annotations

import os
from typing import Optional

_GITHUB_ACTIONS = """\
# AuditLens Security Scan — GitHub Actions
# Generado por: auditlens ci-setup --platform github

name: AuditLens Security Scan

on:
  push:
    branches: [ main, master, develop ]
  pull_request:
    branches: [ main, master ]
  schedule:
    - cron: '0 2 * * 1'   # Lunes 2am UTC

jobs:
  security-scan:
    name: Security Audit
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # para subir SARIF a GitHub Security tab

    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0   # necesario para git-scan (historial completo)

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Install AuditLens
        run: pip install auditlens

      - name: SAST + SCA Scan
        run: |
          auditlens scan . \\
            --format sarif \\
            --output auditlens-results.sarif \\
            --severity LOW \\
            --empresa "${{ vars.EMPRESA_NOMBRE || 'Mi Empresa' }}"
        continue-on-error: true   # no bloquear el build, solo reportar

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: auditlens-results.sarif
          category: auditlens

      - name: Ley 21.719 PII Scan
        run: |
          auditlens ley21719 . \\
            --format json \\
            --output ley21719-results.json \\
            --empresa "${{ vars.EMPRESA_NOMBRE || 'Mi Empresa' }}"
        continue-on-error: true

      - name: Git Secrets Scan
        run: auditlens git-scan . --format json --output git-secrets.json
        continue-on-error: true

      - name: Upload scan artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: auditlens-reports
          path: |
            auditlens-results.sarif
            ley21719-results.json
            git-secrets.json
          retention-days: 30

      - name: Fail on CRITICAL findings
        run: |
          auditlens scan . --severity CRITICAL
        # Este step falla el build si hay hallazgos CRITICAL
"""

_GITLAB_CI = """\
# AuditLens Security Scan — GitLab CI
# Generado por: auditlens ci-setup --platform gitlab

stages:
  - security

variables:
  EMPRESA_NOMBRE: "Mi Empresa"

auditlens-sast:
  stage: security
  image: python:3.11-slim
  before_script:
    - pip install auditlens --quiet
  script:
    - auditlens scan . --format sarif --output gl-sast-report.sarif --severity LOW
    - auditlens ley21719 . --format json --output ley21719-results.json
    - auditlens git-scan . --format json --output git-secrets.json
  artifacts:
    reports:
      sast: gl-sast-report.sarif
    paths:
      - gl-sast-report.sarif
      - ley21719-results.json
      - git-secrets.json
    expire_in: 30 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  allow_failure: true   # no bloquea el pipeline, solo reporta

auditlens-critical-gate:
  stage: security
  image: python:3.11-slim
  needs: []
  before_script:
    - pip install auditlens --quiet
  script:
    - auditlens scan . --severity CRITICAL
    # Falla el pipeline si hay hallazgos CRITICAL
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
"""

_AZURE_DEVOPS = """\
# AuditLens Security Scan — Azure DevOps
# Generado por: auditlens ci-setup --platform azure

trigger:
  branches:
    include:
      - main
      - master
      - develop

pr:
  branches:
    include:
      - main
      - master

pool:
  vmImage: ubuntu-latest

variables:
  EMPRESA_NOMBRE: 'Mi Empresa'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'
    displayName: 'Set up Python'

  - script: pip install auditlens
    displayName: 'Install AuditLens'

  - script: |
      auditlens scan . \\
        --format sarif \\
        --output $(Build.ArtifactStagingDirectory)/auditlens.sarif \\
        --severity LOW
    displayName: 'AuditLens SAST + SCA'
    continueOnError: true

  - script: |
      auditlens ley21719 . \\
        --format json \\
        --output $(Build.ArtifactStagingDirectory)/ley21719.json
    displayName: 'Ley 21.719 PII Scan'
    continueOnError: true

  - task: PublishBuildArtifacts@1
    inputs:
      PathtoPublish: '$(Build.ArtifactStagingDirectory)'
      ArtifactName: 'AuditLens-Reports'
    displayName: 'Publish reports'
    condition: always()

  - script: auditlens scan . --severity CRITICAL
    displayName: 'Critical findings gate'
"""

_BITBUCKET = """\
# AuditLens Security Scan — Bitbucket Pipelines
# Generado por: auditlens ci-setup --platform bitbucket

image: python:3.11-slim

pipelines:
  default:
    - step:
        name: AuditLens Security Scan
        script:
          - pip install auditlens --quiet
          - auditlens scan . --format sarif --output auditlens.sarif --severity LOW
          - auditlens ley21719 . --format json --output ley21719.json
          - auditlens git-scan . --format json --output git-secrets.json
        artifacts:
          - auditlens.sarif
          - ley21719.json
          - git-secrets.json
        after-script:
          - auditlens scan . --severity CRITICAL   # gate

  branches:
    main:
      - step:
          name: Full Security Audit
          script:
            - pip install auditlens --quiet
            - auditlens scan . --format html --output audit-report.html
            - auditlens ley21719 . --format all --output ley21719-informe
          artifacts:
            - audit-report.html
            - ley21719-informe.html
            - ley21719-informe.docx
"""

_MAKEFILE_TARGET = """\
## AuditLens targets — agrega esto a tu Makefile existente

.PHONY: security security-critical ley21719 compliance

security:
\tauditlens scan . --severity LOW --format html --output security-report.html

security-critical:
\tauditlens scan . --severity CRITICAL

ley21719:
\tauditlens ley21719 . --empresa "$(EMPRESA)" --format all --output ley21719-informe

compliance:
\tauditlens scan . --format json --output findings.json
\tauditlens compliance findings.json --format html --output compliance-report.html
"""

_PRECOMMIT_CONFIG = """\
# AuditLens pre-commit hook — agrega a .pre-commit-config.yaml
# O usa: auditlens install-hook

repos:
  - repo: local
    hooks:
      - id: auditlens-scan
        name: AuditLens Security Scan
        entry: auditlens scan
        args: ['--severity', 'HIGH', '--no-sca']
        language: system
        pass_filenames: false
        stages: [commit]
"""


_TEMPLATES = {
    'github':    ('.github/workflows/auditlens.yml', _GITHUB_ACTIONS),
    'gitlab':    ('.gitlab-ci.yml',                   _GITLAB_CI),
    'azure':     ('azure-pipelines.yml',              _AZURE_DEVOPS),
    'bitbucket': ('bitbucket-pipelines.yml',          _BITBUCKET),
    'makefile':  ('Makefile.auditlens',               _MAKEFILE_TARGET),
    'precommit': ('.pre-commit-config.auditlens.yaml',_PRECOMMIT_CONFIG),
}


def generate_ci_template(
    platform: str,
    project_path: str = '.',
    output_path: Optional[str] = None,
) -> str:
    platform = platform.lower()
    if platform not in _TEMPLATES:
        raise ValueError(f'Plataforma no soportada: {platform}. Opciones: {list(_TEMPLATES)}')

    default_path, content = _TEMPLATES[platform]

    if output_path is None:
        if platform == 'github':
            os.makedirs(os.path.join(project_path, '.github', 'workflows'), exist_ok=True)
        output_path = os.path.join(project_path, default_path)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as fh:
        fh.write(content)

    print(f'\033[92m[AuditLens CI]\033[0m Template {platform} generado: {output_path}')
    return output_path


def generate_all_templates(project_path: str = '.') -> List[str]:
    from typing import List as _List
    generated: _List[str] = []
    for platform in _TEMPLATES:
        try:
            path = generate_ci_template(platform, project_path)
            generated.append(path)
        except Exception as e:
            print(f'\033[91m[AuditLens CI]\033[0m Error generando {platform}: {e}')
    return generated
