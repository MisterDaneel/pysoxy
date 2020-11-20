import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pysoxy", # Replace with your own username
    version="0.0.1",
    author="https://github.com/MisterDaneel, Lucio Montero",
    #author_email="lucioric2000@hotmail.com",
    description="pysoxy",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Lucioric2000/DelphiVCL_assessment",
    #packages=setuptools.find_packages(),
    packages=["pysoxy"],
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        ###"Operating System :: OS Independent", #for now only Windows
        "Operating System :: Microsoft :: Windows",
        #"Operating System :: Microsoft :: Windows :: Windows 10",
        # Trove classifiers
        # The full list is here: https://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Development Status :: 2 - Pre-Alpha'],
    python_requires='>=3.6',
)
#python3 setup.py sdist bdist_wheel
#python3 -m twine upload --repository testpypi dist/*
#python3 -m pip install --index-url https://test.pypi.org/simple/ --upgrade --no-deps DelphiVCL-lucioric