from setuptools import setup, find_packages

setup(
    name="auditlens",
    version="0.9.0",
    description="SAST, SCA, IaC, DAST, API, DNS, Git, AWS, GitHub, SBOM, AI Threat Modeling — comprehensive security toolkit.",
    long_description=open("README.md", encoding="utf-8").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="AuditLens Contributors",
    url="https://github.com/anomalyco/auditlens",
    license="MIT",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "auditlens": ["*.yaml"],
    },
    entry_points={
        "console_scripts": [
            "auditlens=auditlens.cli:main",
        ],
    },
    # PKG-02 FIX: require Python 3.9+ (uses X | Y union types, str | None, etc.)
    python_requires=">=3.9",
    # PKG-03 FIX: pin minimum versions to avoid breaking API changes
    install_requires=[
        "pyyaml>=6.0",
        "tree-sitter>=0.21,<0.24",
        "tree-sitter-python>=0.21",
        "tree-sitter-javascript>=0.21",
        "fpdf2>=2.7",
        "requests>=2.28",
        "python-docx>=1.1",
    ],
    extras_require={
        # Optional language support
        "swift": ["tree-sitter-swift>=0.4"],
        "typescript": ["tree-sitter-typescript>=0.21"],
        # Full install
        "all": [
            "tree-sitter-swift>=0.4",
            "tree-sitter-typescript>=0.21",
        ],
        # Development / testing
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "responses>=0.23",
        ],
        # Dashboard
        "dashboard": [
            "flask>=3.0",
            "werkzeug>=3.0",
            "gunicorn>=21.0",
        ],
        # File watcher
        "watch": [
            "watchdog>=4.0",
        ],
        # Excel reports
        "excel": [
            "openpyxl>=3.1",
        ],
        # AI fix suggestions + threat modeling
        "ai": [
            "anthropic>=0.30",
        ],
        # AWS auditing
        "aws": [
            "boto3>=1.34",
        ],
        # API scanning (OpenAPI/Swagger)
        "api": [
            "pyyaml>=6.0",
        ],
        # Web auth scanner (BeautifulSoup)
        "web": [
            "beautifulsoup4>=4.12",
        ],
        # Full install (all optional features)
        "all": [
            "tree-sitter-swift>=0.4",
            "tree-sitter-typescript>=0.21",
            "flask>=3.0",
            "werkzeug>=3.0",
            "gunicorn>=21.0",
            "watchdog>=4.0",
            "openpyxl>=3.1",
            "anthropic>=0.30",
            "boto3>=1.34",
            "beautifulsoup4>=4.12",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    keywords="sast sca security taint-analysis devSecOps static-analysis vulnerability",
)
