from setuptools import setup, find_packages

setup(
    name="apex-psi-verify",
    version="1.0.0",
    description="Post-quantum, hash-anchored content seal verifier. LMS-W4-SHA256 + Ed25519.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Kawaljeet Singh",
    author_email="kawal@apex-psi.example.org",
    url="https://github.com/kawal393/apex-psi-verify",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        # No external runtime deps. Stdlib only.
    ],
    extras_require={
        "flask": ["flask>=2.0"],
    },
    entry_points={
        "console_scripts": [
            "apex-psi-verify = apex_psi_verify.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
    ],
)
