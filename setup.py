import setuptools

with open('README.md', 'r') as fh:
    long_description = fh.read()

setuptools.setup(
    name='DeStringCare',
    version='0.0.1',
    author='Dainis Gorbunovs',
    author_email='dgdev@protonmail.com',
    description='DeStringCare for extracting Android apk secrets',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/DainisGorbunovs/DeStringCare',
    packages=setuptools.find_packages(),
    keywords=['StringCare', 'destringcare', 'decrypt', 'apk', 'secrets'],
    install_requires=[
        'cryptography',
        'pycrypto',
        'pyOpenSSL',
        'pyjks'
    ],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Development Status :: 5 - Production/Stable',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    entry_points={
        'console_scripts': ['destringcare = DeStringCare.destringcare:main'],
    },
)