from setuptools import setup, find_packages

setup(
    name="auditlens",
    version="0.1.0",
    description="Herramienta CLI Integral de Análisis SAST y Diagnóstico Post-Mortem",
    author="Tu Nombre",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "auditlens=auditlens.cli:main",
        ],
    },
    install_params=[],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
)
