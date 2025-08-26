from setuptools import setup, find_packages

# Additional vulnerable dependencies in setup.py
setup(
    name="tasktracker",
    version="1.0.0",
    description="A task tracking web application",
    packages=find_packages(),
    install_requires=[
        "Flask==1.0.2",        # Vulnerable
        "requests==2.20.0",    # Vulnerable  
        "SQLAlchemy==1.2.12",  # Outdated
        "Pillow==6.2.0",       # Vulnerable
    ],
    extras_require={
        "dev": [
            "pytest==4.6.5",   # Outdated
            "coverage==4.5.4", # Outdated
        ]
    },
    python_requires=">=3.6",
)