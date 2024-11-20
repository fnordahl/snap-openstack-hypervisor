# Copyright 2024 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import click

from openstack_hypervisor.cli.hypervisor import hypervisor
from openstack_hypervisor.cli.interfaces import list_nics
from openstack_hypervisor.cli.log import setup_root_logging

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


@click.group("init", context_settings=CONTEXT_SETTINGS)
@click.option("-v", "--verbose", is_flag=True, help="Increase output verbosity")
def cli(verbose: bool):
    """Set of utilities for managing the hypervisor."""


def main():
    """Register commands and run the CLI."""
    setup_root_logging()
    cli.add_command(list_nics)
    cli.add_command(hypervisor)

    cli()


if __name__ == "__main__":
    main()
