from setuptools import setup, find_packages

VERSION = '0.1'
DESCRIPTION = 'Api Wrapper for KeyAuth.com'
LONG_DESCRIPTION = 'Api Wrapper in Python made for KeyAuth.com'

# Setting up
setup(
    name="keyauthy",
    version=VERSION,
    author="Mohanad Hosny",
    description=DESCRIPTION,
    long_description_content_type="text/markdown",
    long_description=LONG_DESCRIPTION,
    packages=find_packages(),
    install_requires=['requests', 'pycryptodome'],
    keywords=['wrapper', 'apiwrapper', 'keyauth', 'auth', 'authsystem'],
    classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Operating System :: Unix",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
    ]
)
