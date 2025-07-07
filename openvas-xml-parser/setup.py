from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="openvas-xml-parser",
    version="1.0.0",
    author="Haseeb-1698",
    author_email="haseeb@example.com",
    description="Convert OpenVAS XML reports to structured JSON format",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Haseeb-1698/CyberPulse",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Text Processing :: Markup :: XML",
    ],
    python_requires=">=3.8",
    install_requires=[
        "lxml>=4.9.0",
    ],
    entry_points={
        "console_scripts": [
            "openvas-parser=openvas_parser.parser:main",
        ],
    },
    keywords="openvas, xml, json, security, vulnerability, scanning",
    project_urls={
        "Bug Reports": "https://github.com/Haseeb-1698/CyberPulse/issues",
        "Source": "https://github.com/Haseeb-1698/CyberPulse",
        "Documentation": "https://github.com/Haseeb-1698/CyberPulse#readme",
    },
)
