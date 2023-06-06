import setuptools

setuptools.setup(
    name="libdebug",
    version="0.4",
    author="JinBlack",
    description="A library to debug binary programs",
    packages=["libdebug"],
    install_requires=[
        'capstone',
    ]
)