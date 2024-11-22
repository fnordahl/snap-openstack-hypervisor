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
from unittest.mock import MagicMock, patch

import pytest

from openstack_hypervisor.cli.interfaces import filter_candidate_nics

INTERFACES = [
    {
        "ifname": "eth0",
        "slave_kind": None,
        "kind": "eth",
        "ipaddr": [{"address": "192.168.1.1"}],
    },
    {
        "ifname": "eth1",
        "slave_kind": "bond",
        "kind": "eth",
        "ipaddr": [{"address": "192.168.1.2"}],
    },
    {
        "ifname": "eth2",
        "slave_kind": None,
        "kind": "eth",
        "ipaddr": [],
    },
    {
        "ifname": "vlan0",
        "slave_kind": None,
        "kind": "vlan",
        "ipaddr": [{"address": "fe80::1"}],  # link local
    },
    {
        "ifname": "bond0",
        "slave_kind": None,
        "kind": "bond",
        "ipaddr": [{"address": "192.168.1.3"}],
    },
    {
        "ifname": "bond1",
        "slave_kind": None,
        "kind": "bond",
        "ipaddr": [],
    },
]


@pytest.fixture
def mock_interfaces():
    nics = []
    for interface in INTERFACES:
        iface = MagicMock()
        iface.__getitem__.side_effect = interface.__getitem__
        iface.ipaddr.summary.return_value = interface["ipaddr"]
        nics.append(iface)

    return nics


@patch(
    "openstack_hypervisor.cli.interfaces.load_virtual_interfaces",
    return_value=["vlan0", "bond0", "bond1"],
)
def test_filter_candidate_nics(mock_load_virtual_interfaces, mock_interfaces):
    result = filter_candidate_nics(mock_interfaces)
    assert result == ["eth0", "eth2", "vlan0", "bond0", "bond1"]
