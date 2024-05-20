#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from lxml import etree

from libdebug.qemu_stub.qemu_register_definition import QemuRegisterDefinition


def parse_qemu_target_xml(xml_data: str) -> list[QemuRegisterDefinition]:
    """Parses the XML data of the QEMU target and returns a dictionary with the register definitions.

    Args:
        xml_data (str): The XML data of the QEMU target.

    Returns:
        dict: A dictionary with the register definitions.
    """
    register_definitions = []
    current_offset = 0

    root = etree.fromstring(xml_data)

    # Iterate over all the children of the root element
    for child in root:
        # Select the 'reg' elements
        if child.tag == "reg":
            name = child.attrib["name"]
            size = int(child.attrib["bitsize"]) // 8

            # Create a new register definition
            register_definitions.append(
                QemuRegisterDefinition(name, current_offset, size)
            )

            # Update the current offset
            current_offset += size

    # TODO what about overlapping registers (e.g., x86_64 RAX and EAX)?

    return register_definitions
