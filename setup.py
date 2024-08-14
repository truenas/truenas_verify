from setuptools import find_packages, setup


setup(
    name='truenas_verify',
    version='0.0.1',
    description='TrueNAS SCALE File Hash Verification',
    packages=find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
    ],
    install_requires=[],
    entry_points={
        'console_scripts': [
            'truenas_verify = truenas_verify.mtree_verify:main',
        ],
    },
)