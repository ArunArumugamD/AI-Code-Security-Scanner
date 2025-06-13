from setuptools import setup, find_packages

setup(
    name="aisec-scanner",
    version="0.1.0",
    author="Your Name",
    description="Advanced AI-powered code security scanner",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.9",
    install_requires=[
        line.strip() 
        for line in open("requirements.txt") 
        if line.strip() and not line.startswith("#")
    ],
    entry_points={
        "console_scripts": [
            "aisec-scan=cli.main:main",
        ],
    },
)
