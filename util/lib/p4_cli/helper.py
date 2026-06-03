# Copyright 2019 Belma Turkovic
# TU Delft Embedded and Networked Systems Group.
# NOTICE: THIS FILE IS BASED ON https://github.com/p4lang/tutorials/tree/master/exercises/p4runtime, BUT WAS MODIFIED UNDER COMPLIANCE
# WITH THE APACHE 2.0 LICENCE FROM THE ORIGINAL WORK. THE FOLLOWING IS THE COPYRIGHT OF THE ORIGINAL DOCUMENT:
#
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""P4Info Helper Utilities for P4Runtime Programming.

This module provides utility classes and functions for working with P4Info metadata
and building P4Runtime protocol buffer messages. It simplifies the construction of
table entries, match fields, actions, and packet operations by providing a convenient
wrapper around the P4Info protobuf.

Classes:
    P4InfoHelper: Helper class for P4Info parsing and message construction
"""

import re

import google.protobuf.text_format
from util.lib.p4.v1 import p4runtime_pb2
from util.lib.p4.config.v1 import p4info_pb2

from .convert import encode


class P4InfoHelper(object):
    """Helper class for parsing P4Info and constructing P4Runtime messages.
    
    This class provides convenient methods for working with P4Info metadata files.
    It allows you to look up IDs from names, retrieve match field and action information,
    and build protobuf messages for table entries, match fields, actions, and packet operations.
    
    Attributes:
        p4info (P4Info): Parsed P4Info protobuf containing program metadata
    """

    def __init__(self, p4_info_filepath):
        """Initialize the P4InfoHelper by loading a P4Info file.
        
        Args:
            p4_info_filepath (str): Path to the P4Info text file to load
        
        Raises:
            FileNotFoundError: If the P4Info file does not exist
            ParseError: If the P4Info file is not valid text format protobuf
        """
        p4info = p4info_pb2.P4Info()
        # Load the p4info file into a skeleton P4Info object
        with open(p4_info_filepath) as p4info_f:
            google.protobuf.text_format.Merge(p4info_f.read(), p4info)
        self.p4info = p4info

    def get(self, entity_type, name=None, id=None):
        """Retrieve a P4 entity (table, action, etc.) by name or ID.
        
        Args:
            entity_type (str): Type of entity to retrieve (e.g., 'tables', 'actions', 'counters')
            name (str, optional): Name or alias of the entity. Defaults to None.
            id (int, optional): ID of the entity. Defaults to None.
        
        Returns:
            Entity protobuf object with matching name or ID
        
        Raises:
            AssertionError: If both name and id are provided
            AttributeError: If entity not found by name or ID
        
        Note:
            Exactly one of name or id must be provided (not both).
        """
        if name is not None and id is not None:
            raise AssertionError("name or id should be provided, not both")
        for o in getattr(self.p4info, entity_type):
            pre = o.preamble
            if name:
                if pre.name == name or pre.alias == name:
                    return o
            else:
                if pre.id == id:
                    return o

        if name:
            raise AttributeError(
                "Could not find %r of type %s" % (name, entity_type))
        else:
            raise AttributeError(
                "Could not find id %r of type %s" % (id, entity_type))

    def get_id(self, entity_type, name):
        """Get the numeric ID of an entity by its name.
        
        Args:
            entity_type (str): Type of entity (e.g., 'tables', 'actions')
            name (str): Name of the entity
        
        Returns:
            int: The numeric ID of the entity
        
        Raises:
            AttributeError: If entity with given name not found
        """
        return self.get(entity_type, name=name).preamble.id

    def get_name(self, entity_type, id):
        """Get the name of an entity by its numeric ID.
        
        Args:
            entity_type (str): Type of entity (e.g., 'tables', 'actions')
            id (int): Numeric ID of the entity
        
        Returns:
            str: The name of the entity
        
        Raises:
            AttributeError: If entity with given ID not found
        """
        return self.get(entity_type, id=id).preamble.name

    def get_alias(self, entity_type, id):
        """Get the alias of an entity by its numeric ID.
        
        Args:
            entity_type (str): Type of entity (e.g., 'tables', 'actions')
            id (int): Numeric ID of the entity
        
        Returns:
            str: The alias of the entity
        
        Raises:
            AttributeError: If entity with given ID not found
        """
        return self.get(entity_type, id=id).preamble.alias

    def __getattr__(self, attr):
        """Enable dynamic convenience methods for name/ID lookups.
        
        Synthesizes methods like:
        - get_tables_id(name) - Returns table ID from name
        - get_tables_name(id) - Returns table name from ID
        - get_actions_id(name) - Returns action ID from name
        - get_actions_name(id) - Returns action name from ID
        - etc. for any P4 entity type
        
        Args:
            attr (str): Method name being called
        
        Returns:
            Callable: Function that performs the lookup
        
        Raises:
            AttributeError: If method name doesn't match the pattern
        """
        # Synthesize convenience functions for name to id lookups for top-level entities
        # e.g. get_tables_id(name_string) or get_actions_id(name_string)
        m = re.search("^get_(\w+)_id$", attr)
        if m:
            primitive = m.group(1)
            return lambda name: self.get_id(primitive, name)

        # Synthesize convenience functions for id to name lookups
        # e.g. get_tables_name(id) or get_actions_name(id)
        m = re.search("^get_(\w+)_name$", attr)
        if m:
            primitive = m.group(1)
            return lambda id: self.get_name(primitive, id)

        raise AttributeError("%r object has no attribute %r" %
                             (self.__class__, attr))

    def get_match_field(self, table_name, name=None, id=None):
        """Retrieve match field metadata for a table.
        
        Args:
            table_name (str): Name of the table
            name (str, optional): Name of the match field. Defaults to None.
            id (int, optional): ID of the match field. Defaults to None.
        
        Returns:
            MatchField: Match field protobuf object
        
        Raises:
            AttributeError: If table or match field not found
        
        Note:
            Exactly one of name or id should be provided.
        """
        for t in self.p4info.tables:
            pre = t.preamble
            if pre.name == table_name:
                for mf in t.match_fields:
                    if name is not None:
                        if mf.name == name:
                            return mf
                    elif id is not None:
                        if mf.id == id:
                            return mf
        raise AttributeError(
            "%r has no attribute %r" % (
                table_name, name if name is not None else id)
        )

    def get_match_field_id(self, table_name, match_field_name):
        """Get the numeric ID of a match field.
        
        Args:
            table_name (str): Name of the table
            match_field_name (str): Name of the match field
        
        Returns:
            int: The numeric ID of the match field
        
        Raises:
            AttributeError: If match field not found
        """
        return self.get_match_field(table_name, name=match_field_name).id

    def get_match_field_name(self, table_name, match_field_id):
        """Get the name of a match field by its ID.
        
        Args:
            table_name (str): Name of the table
            match_field_id (int): Numeric ID of the match field
        
        Returns:
            str: The name of the match field
        
        Raises:
            AttributeError: If match field not found
        """
        return self.get_match_field(table_name, id=match_field_id).name

    def get_match_field_bitwidth(self, table_name, match_field_id):
        """Get the name of a match field by its ID.
        
        Args:
            table_name (str): Name of the table
            match_field_id (int): Numeric ID of the match field
        
        Returns:
            int: The bitwidth of the match field
        
        Raises:
            AttributeError: If match field not found
        """
        return self.get_match_field(table_name, id=match_field_id).bitwidth

    def get_match_field_pb(self, table_name, match_field_name, value):
        """Build a P4Runtime FieldMatch protobuf for a table match field.
        
        Converts a match value into the appropriate protobuf format based on the
        match type (exact, LPM, ternary, range, valid).
        
        Args:
            table_name (str): Name of the table
            match_field_name (str): Name of the match field
            value: Match value in format appropriate for the match type:
                - EXACT: single value
                - LPM: tuple (value, prefix_len)
                - TERNARY: tuple (value, mask)
                - RANGE: tuple (low, high)
                - VALID: boolean
        
        Returns:
            FieldMatch: P4Runtime FieldMatch protobuf
        
        Raises:
            Exception: If match type is unsupported
        """
        p4info_match = self.get_match_field(table_name, match_field_name)
        bitwidth = p4info_match.bitwidth
        p4runtime_match = p4runtime_pb2.FieldMatch()
        p4runtime_match.field_id = p4info_match.id
        match_type = p4info_match.match_type
        # change vaild => to unspecified
        if match_type == p4info_pb2.MatchField.UNSPECIFIED:
            valid = p4runtime_match.valid
            valid.value = bool(value)
        elif match_type == p4info_pb2.MatchField.EXACT:
            exact = p4runtime_match.exact
            exact.value = encode(value, bitwidth)
        elif match_type == p4info_pb2.MatchField.LPM:
            lpm = p4runtime_match.lpm
            lpm.value = encode(value[0], bitwidth)
            lpm.prefix_len = value[1]
        elif match_type == p4info_pb2.MatchField.TERNARY:
            lpm = p4runtime_match.ternary
            lpm.value = encode(value[0], bitwidth)
            lpm.mask = encode(value[1], bitwidth)
        elif match_type == p4info_pb2.MatchField.RANGE:
            lpm = p4runtime_match.range
            lpm.low = encode(value[0], bitwidth)
            lpm.high = encode(value[1], bitwidth)
        else:
            raise Exception("Unsupported match type with type %r" % match_type)
        return p4runtime_match

    def get_match_field_value(self, match_field):
        """Extract the match value from a P4Runtime FieldMatch protobuf.
        
        Parses a FieldMatch and returns the underlying value in a Python-friendly format.
        
        Args:
            match_field (FieldMatch): P4Runtime FieldMatch protobuf
        
        Returns:
            Match value in format appropriate for type:
            - VALID: boolean
            - EXACT: bytes value
            - LPM: tuple (value, prefix_len)
            - TERNARY: tuple (value, mask)
            - RANGE: tuple (low, high)
        
        Raises:
            Exception: If match type is unsupported
        """
        match_type = match_field.WhichOneof("field_match_type")
        if match_type == "valid":
            return match_field.valid.value
        elif match_type == "exact":
            return match_field.exact.value
        elif match_type == "lpm":
            return (match_field.lpm.value, match_field.lpm.prefix_len)
        elif match_type == "ternary":
            return (match_field.ternary.value, match_field.ternary.mask)
        elif match_type == "range":
            return (match_field.range.low, match_field.range.high)
        else:
            raise Exception("Unsupported match type with type %r" % match_type)

    def get_action_param(self, action_name, name=None, id=None):
        """Retrieve action parameter metadata.
        
        Args:
            action_name (str): Name of the action
            name (str, optional): Name of the parameter. Defaults to None.
            id (int, optional): ID of the parameter. Defaults to None.
        
        Returns:
            Param: Action parameter protobuf object
        
        Raises:
            AttributeError: If action or parameter not found
        
        Note:
            Exactly one of name or id should be provided.
        """
        for a in self.p4info.actions:
            pre = a.preamble
            if pre.name == action_name:
                for p in a.params:
                    if name is not None:
                        if p.name == name:
                            return p
                    elif id is not None:
                        if p.id == id:
                            return p
        raise AttributeError(
            "action %r has no param %r, (has: %r)"
            % (action_name, name if name is not None else id, a.params)
        )

    def get_action_param_id(self, action_name, param_name):
        """Get the numeric ID of an action parameter.
        
        Args:
            action_name (str): Name of the action
            param_name (str): Name of the parameter
        
        Returns:
            int: The numeric ID of the parameter
        
        Raises:
            AttributeError: If parameter not found
        """
        return self.get_action_param(action_name, name=param_name).id

    def get_action_param_name(self, action_name, param_id):
        """Get the name of an action parameter by its ID.
        
        Args:
            action_name (str): Name of the action
            param_id (int): Numeric ID of the parameter
        
        Returns:
            str: The name of the parameter
        
        Raises:
            AttributeError: If parameter not found
        """
        return self.get_action_param(action_name, id=param_id).name

    def get_action_param_bitwidth(self, action_name, param_id):
        """Get the name of an action parameter by its ID.
        
        Args:
            action_name (str): Name of the action
            param_id (int): Numeric ID of the parameter
        
        Returns:
            str: The name of the parameter
        
        Raises:
            AttributeError: If parameter not found
        """
        return self.get_action_param(action_name, id=param_id).bitwidth

    def get_action_param_pb(self, action_name, param_name, value):
        """Build a P4Runtime Action.Param protobuf for an action parameter.
        
        Args:
            action_name (str): Name of the action
            param_name (str): Name of the parameter
            value: Parameter value to encode
        
        Returns:
            Action.Param: P4Runtime action parameter protobuf
        """
        p4info_param = self.get_action_param(action_name, param_name)
        p4runtime_param = p4runtime_pb2.Action.Param()
        p4runtime_param.param_id = p4info_param.id
        p4runtime_param.value = encode(value, p4info_param.bitwidth)
        return p4runtime_param

    def get_replicas_pb(self, egress_port, instance):
        """Build a P4Runtime Replica protobuf for multicast replication.
        
        Args:
            egress_port (int): Output port number for the replica
            instance (int): Instance ID for this replica
        
        Returns:
            Replica: P4Runtime replica configuration protobuf
        """
        p4runtime_replicas = p4runtime_pb2.Replica()
        p4runtime_replicas.egress_port = egress_port
        p4runtime_replicas.instance = instance
        return p4runtime_replicas

    def get_metadata_pb(self, metadata_id, value):
        """Build a P4Runtime PacketMetadata protobuf.
        
        Args:
            metadata_id (int): Numeric ID of the metadata field
            value (bytes): Metadata value to include
        
        Returns:
            PacketMetadata: P4Runtime packet metadata protobuf
        """
        p4runtime_metadata = p4runtime_pb2.PacketMetadata()
        p4runtime_metadata.metadata_id = metadata_id
        p4runtime_metadata.value = value
        return p4runtime_metadata

    def buildMCEntry(self, mc_group_id, replicas=None):
        """Build a multicast group entry for packet replication.
        
        Args:
            mc_group_id (int): Multicast group ID to create/update
            replicas (list, optional): List of replica dicts with 'egress_port' and
                'instance' keys. If None, creates empty group. Defaults to None.
        
        Returns:
            PacketReplicationEngineEntry: PRE entry with multicast group configuration
        
        Example:
            >>> replicas = [
            ...     {"egress_port": 1, "instance": 0},
            ...     {"egress_port": 2, "instance": 0}
            ... ]
            >>> mc_entry = helper.buildMCEntry(1, replicas)
        """
        mc_entry = p4runtime_pb2.PacketReplicationEngineEntry()
        mc_entry.multicast_group_entry.multicast_group_id = mc_group_id
        if replicas:
            mc_entry.multicast_group_entry.replicas.extend(
                [
                    self.get_replicas_pb(
                        replica["egress_port"], replica["instance"])
                    for replica in replicas
                ]
            )
        return mc_entry

    def buildPacketOut(self, payload, metadata=None):
        """Build a P4Runtime PacketOut message for sending control packets.
        
        Args:
            payload (bytes): Packet payload data to send
            metadata (dict, optional): Dictionary mapping metadata IDs to values.
                Defaults to None (no metadata).
        
        Returns:
            PacketOut: P4Runtime packet-out protobuf
        
        Example:
            >>> metadata = {1: b'\\x00\\x02'}  # Port 2
            >>> packet = helper.buildPacketOut(b'\\x00\\x11\\x22\\x33', metadata)
        """
        packet_out = p4runtime_pb2.PacketOut()
        packet_out.payload = payload
        if metadata:
            packet_out.metadata.extend(
                [
                    self.get_metadata_pb(metadata_id, value)
                    for metadata_id, value in metadata.items()
                ]
            )
        return packet_out

    def buildTableEntry(
        self,
        table_name,
        match_fields=None,
        default_action=False,
        action_name=None,
        action_params=None,
        priority=None,
    ):
        """Build a P4Runtime TableEntry protobuf.
        
        Constructs a complete table entry with match fields, action, and parameters.
        
        Args:
            table_name (str): Name of the table to insert into
            match_fields (dict, optional): Dictionary mapping match field names to values.
                Defaults to None (no match criteria).
            default_action (bool, optional): If True, this is a default action entry.
                Defaults to False.
            action_name (str, optional): Name of the action to execute.
                Defaults to None (no action).
            action_params (dict, optional): Dictionary mapping parameter names to values.
                Defaults to None (no parameters).
            priority (int, optional): Priority value for ternary/range matches.
                Defaults to None (no priority).
        
        Returns:
            TableEntry: P4Runtime table entry protobuf
        
        Example:
            >>> entry = helper.buildTableEntry(
            ...     table_name="ipv4_lpm",
            ...     match_fields={"hdr.ipv4.dstAddr": ("192.168.1.0", 24)},
            ...     action_name="set_nhop",
            ...     action_params={"port": 1}
            ... )
        """
        table_entry = p4runtime_pb2.TableEntry()
        table_entry.table_id = self.get_tables_id(table_name)

        if priority is not None:
            table_entry.priority = priority

        if match_fields:
            table_entry.match.extend(
                [
                    self.get_match_field_pb(
                        table_name, match_field_name, value)
                    for match_field_name, value in match_fields.items()
                ]
            )

        if default_action:
            table_entry.is_default_action = True

        if action_name:
            action = table_entry.action.action
            action.action_id = self.get_actions_id(action_name)
            if action_params:
                action.params.extend(
                    [
                        self.get_action_param_pb(
                            action_name, field_name, value)
                        for field_name, value in action_params.items()
                    ]
                )
        return table_entry
