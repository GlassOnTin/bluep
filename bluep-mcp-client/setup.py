"""Setup script for bluep-mcp-client standalone package."""

from setuptools import setup, find_packages

setup(
    name="bluep-mcp-client",
    version="0.1.0",
    description="Standalone MCP client proxy for bluep",
    author="bluep contributors",
    python_requires=">=3.7",
    packages=find_packages(),
    install_requires=[
        "websockets>=10.0",
        "aiohttp>=3.8.0",
        "click>=8.0",
    ],
    entry_points={
        "console_scripts": [
            "bluep-mcp=bluep_mcp_client.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)