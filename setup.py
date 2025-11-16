from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="netforensic-toolkit",
    version="1.0.0",
    author="Syed Rai",
    author_email="your-email@example.com",
    description="Professional network forensic analysis toolkit with cartoonish interface",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.10",
    install_requires=[
        "scapy>=2.4.5",
        "dpkt>=1.9.8", 
        "pandas>=1.5.0",
        "matplotlib>=3.6.0",
        "argcomplete>=2.0.0",
        "colorama>=0.4.6",
    ],
    entry_points={
        "console_scripts": [
            "netforensic=netforensic.cli:main",
        ],
    },
    include_package_data=True,
)
