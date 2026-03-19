"""Setup script for RubyGuardian ML Classifier."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [
        line.strip()
        for line in fh
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="rubyguardian-ml-classifier",
    version="0.3.0",
    author="RubyGuardian Team",
    author_email="team@rubyguardian.dev",
    description="ML-based malware classification pipeline for Ruby scripts",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rubyguardian/rubyguardian",
    packages=find_packages(exclude=["tests*", "notebooks*"]),
    python_requires=">=3.10",
    install_requires=requirements,
    extras_require={
        "api": [
            "fastapi>=0.104.0",
            "uvicorn[standard]>=0.24.0",
            "python-multipart>=0.0.6",
            "slowapi>=0.1.9",
            "python-jose[cryptography]>=3.3.0",
        ],
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-asyncio>=0.21.0",
            "httpx>=0.25.0",
            "black>=23.9.0",
            "ruff>=0.1.0",
            "mypy>=1.6.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "rg-extract=feature_extraction.feature_pipeline:main",
            "rg-train=models.training.train_pipeline:main",
            "rg-evaluate=models.evaluation.evaluator:main",
            "rg-serve=api.app:run_server",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
