from setuptools import setup, find_packages

setup(
    name="libdebug",
    version="0.3",
    author="JinBlack",
    description="A library to debug binary programs",
    packages=find_packages(include=["libdebug", "libdebug.*"]),
    install_requires=[
        "capstone",
        "pyelftools",
    ],
)
