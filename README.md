# ns8-idp

Single sign-on and identity federation for NethServer 8 applications, based on Keycloak

## Install

Install the module (application) on cluster node 1:

    add-module ghcr.io/nethserver/idp:1.0.0 1

The output of the command will return the module identifier:
Output example:

    {"module_id": "idp1", "image_name": "idp", "image_url": "ghcr.io/nethserver/idp:1.0.0"}

## Configure

Work in progress...

## Uninstall

To uninstall the instance:

    remove-module --no-preserve idp1

## Running tests locally

This module uses the NS8 standard testing infrastructure. For instructions on how to run the test suite locally, refer to the [Running tests locally](https://github.com/NethServer/ns8-github-actions/blob/v1/README.md#running-tests-locally) section of the ns8-github-actions README.

## UI translation

Translated with [Weblate](https://hosted.weblate.org/projects/ns8/).

To setup the translation process:

- add [GitHub Weblate app](https://docs.weblate.org/en/latest/admin/continuous.html#github-setup) to your repository
- add your repository to [hosted.weblate.org](https://hosted.weblate.org) or ask a NethServer developer to add it to ns8 Weblate project
