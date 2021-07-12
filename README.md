# sloth-ci.validators.bitbucket

Sloth CI validator for [Bitbucket](https://bitbucket.org/) push events.


## Installation
    
    $ pip install sloth-ci.validators.bitbucket


## Usage

    provider:
        bitbucket:
            # Repository owner. Mandatory parameter.
            owner: moigagoo

            # Repository title as it appears in the URL, i.e. slug.
            # Mandatory parameter.
            repo: sloth-ci

            # Only pushes to these branches will initiate a build.
            # Skip this parameter to allow all branches to fire builds.
            branches:
                - master
                - staging
