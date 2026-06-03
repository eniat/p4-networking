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
"""P4Runtime Switch Connection Management Module.

This module provides a gRPC-based client for communicating with P4Runtime-enabled
switches. It handles device configuration, table entry management, counter operations,
and packet I/O through a P4Runtime interface.

Classes:
    SwitchConnection: Main class for P4Runtime switch communication
    GrpcRequestLogger: Interceptor for logging gRPC requests
    IterableQueue: Queue wrapper for iteration support

Functions:
    ShutdownAllSwitchConnections: Cleanup all active switch connections
"""

from abc import abstractmethod
from datetime import datetime
from queue import Queue

import grpc
from util.lib.p4.tmp import p4config_pb2
from util.lib.p4.v1 import p4runtime_pb2, p4runtime_pb2_grpc

MSG_LOG_MAX_LEN = 1024

# List of all active connections
connections = []


def ShutdownAllSwitchConnections():
    """Shutdown all active P4Runtime switch connections.

    Iterates through the global connections list and calls shutdown() on each
    active SwitchConnection to gracefully close gRPC channels and streams.
    """
    for c in connections:
        c.shutdown()


class SwitchConnection(object):
    """Client for communicating with P4Runtime-enabled switches via gRPC.

    This class manages the connection to a single P4Runtime device and provides
    methods for configuration, table operations, counter reading, and packet I/O.
    Automatically registers itself globally for lifecycle management.

    Attributes:
        name (str): Friendly name for the switch connection
        address (str): gRPC server address in format 'host:port'
        device_id (int): Unique device identifier for the switch
        p4info (P4Info): Parsed P4Info protobuf from the device
        channel (grpc.Channel): gRPC channel to the switch
        client_stub (P4RuntimeStub): P4Runtime service stub
        requests_stream (IterableQueue): Queue for outgoing StreamChannel messages
        stream_msg_resp: Streaming response iterator from StreamChannel
    """

    def __init__(self, name=None, address='127.0.0.1:50051', device_id=0,
                 proto_dump_file=None):
        """Initialize a P4Runtime switch connection.

        Args:
            name (str, optional): Descriptive name for this connection. Defaults to None.
            address (str, optional): gRPC server endpoint. Defaults to '127.0.0.1:50051'.
            device_id (int, optional): Device ID for this switch. Defaults to 0.
            proto_dump_file (str, optional): Path to file for logging gRPC messages.
                If provided, all requests are logged to this file. Defaults to None.

        Note:
            This connection is automatically added to the global connections list
            for lifecycle management via ShutdownAllSwitchConnections().
        """
        self.name = name
        self.address = address
        self.device_id = device_id
        self.p4info = None
        self.channel = grpc.insecure_channel(self.address)
        if proto_dump_file is not None:
            interceptor = GrpcRequestLogger(proto_dump_file)
            self.channel = grpc.intercept_channel(self.channel, interceptor)
        self.client_stub = p4runtime_pb2_grpc.P4RuntimeStub(self.channel)
        self.requests_stream = IterableQueue()
        self.stream_msg_resp = self.client_stub.StreamChannel(
            iter(self.requests_stream))
        self.proto_dump_file = proto_dump_file
        connections.append(self)

    @abstractmethod
    def buildDeviceConfig(self, **kwargs):
        """Build device-specific P4 configuration.

        Subclasses must implement this method to provide device-specific configuration
        in P4DeviceConfig protobuf format. This is used during pipeline configuration.

        Args:
            **kwargs: Device-specific configuration parameters

        Returns:
            P4DeviceConfig: Device configuration protobuf message

        Note:
            This is an abstract method that must be overridden in subclasses.
        """
        return p4config_pb2.P4DeviceConfig()

    def shutdown(self):
        """Gracefully shutdown the switch connection.

        Closes the request stream and cancels the response stream to cleanly
        terminate the gRPC bidirectional streaming connection.
        """
        self.requests_stream.close()
        self.stream_msg_resp.cancel()

    def MasterArbitrationUpdate(self, dry_run=False, **kwargs):
        """Send master arbitration request to establish primary controller.

        Acquires controller mastership for this device by sending an arbitration
        update with election ID. This must be done before any other operations.

        Args:
            dry_run (bool, optional): If True, print request without sending.
                Defaults to False.
            election_id (int, optional): Election ID for master arbitration.
                If None, defaults to (high=0, low=1).
            **kwargs: Additional arguments (unused, for interface compatibility)

        Returns:
            StreamMessageResponse: Response from device arbitration process

        Note:
            Uses a fixed election ID (high=0, low=1). Only one master can be active.
        """
        request = p4runtime_pb2.StreamMessageRequest()
        request.arbitration.device_id = self.device_id
        request.arbitration.election_id.high = 0
        request.arbitration.election_id.low = 1

        if dry_run:
            print("P4Runtime MasterArbitrationUpdate: ", request)
        else:
            self.requests_stream.put(request)
            for item in self.stream_msg_resp:
                return item  # just one

    def SetForwardingPipelineConfig(self, p4info, dry_run=False, **kwargs):
        """Configure the P4 forwarding pipeline on the device.

        Loads the P4Info and device configuration onto the switch. This must be
        called after master arbitration and before any table operations.

        Args:
            p4info (P4Info): Parsed P4Info protobuf containing program metadata
            dry_run (bool, optional): If True, print request without sending.
                Defaults to False.
            **kwargs: Device-specific configuration arguments passed to buildDeviceConfig()

        Raises:
            grpc.RpcError: If the configuration fails on the device
        """
        device_config = self.buildDeviceConfig(**kwargs)
        request = p4runtime_pb2.SetForwardingPipelineConfigRequest()
        request.election_id.low = 1
        request.device_id = self.device_id
        config = request.config

        config.p4info.CopyFrom(p4info)
        config.p4_device_config = device_config.SerializeToString()

        request.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT
        if dry_run:
            print("P4Runtime SetForwardingPipelineConfig:", request)
        else:
            self.client_stub.SetForwardingPipelineConfig(request)

    def WriteTableEntry(self, table_entry, dry_run=False):
        """Insert or modify a forwarding table entry.

        Sends a table entry to the device. Automatically detects whether this is
        a default action (MODIFY) or a regular entry (INSERT).

        Args:
            table_entry (TableEntry): Table entry protobuf to write
            dry_run (bool, optional): If True, print request without sending.
                Defaults to False.

        Raises:
            grpc.RpcError: If the write operation fails on the device
        """
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        if table_entry.is_default_action:
            update.type = p4runtime_pb2.Update.MODIFY
        else:
            update.type = p4runtime_pb2.Update.INSERT
        update.entity.table_entry.CopyFrom(table_entry)
        if dry_run:
            print("P4Runtime Write:", request)
        else:
            self.client_stub.Write(request)

    def DeleteTableEntry(self, table_entry, dry_run=False):
        """Delete a forwarding table entry.

        Sends a table entry to the device to delete it.

        Args:
            table_entry (TableEntry): Table entry protobuf to delete
            dry_run (bool, optional): If True, print request without sending.
                Defaults to False.

        Raises:
            grpc.RpcError: If the write operation fails on the device
        """
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.DELETE
        update.entity.table_entry.CopyFrom(table_entry)
        if dry_run:
            print("P4Runtime Delete:", request)
        else:
            self.client_stub.Write(request)

    def ReadTableEntries(self, table_id=None, dry_run=False):
        """Read table entries from the device.

        Queries the switch for all table entries, optionally filtered by table ID.

        Args:
            table_id (int, optional): Specific table ID to read. If None, reads all
                tables. Defaults to None.
            dry_run (bool, optional): If True, print request without sending.
                Defaults to False.

        Yields:
            ReadResponse: Response messages from the device containing table entries
        """
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        table_entry = entity.table_entry
        if table_id is not None:
            table_entry.table_id = table_id
        else:
            table_entry.table_id = 0
        if dry_run:
            print("P4Runtime Read:", request)
        else:
            for response in self.client_stub.Read(request):
                yield response

    def PacketIn(self, dry_run=False, **kwargs):
        """Receive a packet-in message from the device.

        Waits for and returns the next packet-in message from the switch's streaming
        connection. These are typically control plane packets that need special handling.

        Args:
            dry_run (bool, optional): If True, print request without sending.
                Defaults to False.
            **kwargs: Additional arguments (unused, for interface compatibility)

        Returns:
            StreamMessageResponse: Packet-in message from the device
        """
        for item in self.stream_msg_resp:
            if dry_run:
                print("P4 Runtime PacketIn: ", request)
            else:
                return item

    def PacketOut(self, packet, dry_run=False, **kwargs):
        """Send a packet-out message to the device.

        Sends a control plane packet to be processed by the switch. The packet
        includes metadata specifying output ports and other forwarding actions.

        Args:
            packet (PacketOut): Packet-out message protobuf to send
            dry_run (bool, optional): If True, print request without sending.
                Defaults to False.
            **kwargs: Additional arguments (unused, for interface compatibility)

        Returns:
            StreamMessageRequest: The request message sent to the device
        """
        request = p4runtime_pb2.StreamMessageRequest()
        request.packet.CopyFrom(packet)
        if dry_run:
            print("P4 Runtime: ", request)
        else:
            self.requests_stream.put(request)
            # for item in self.stream_msg_resp:
            return request

    def ReadCounters(self, counter_id=None, index=None, dry_run=False):
        """Read counter values from the device.

        Queries counter state from the switch, optionally filtered by counter ID
        and index. Counters track packet/byte statistics for tables and other entities.

        Args:
            counter_id (int, optional): Specific counter ID to read. If None, reads
                all counters. Defaults to None.
            index (int, optional): Specific index within the counter array to read.
                If None, reads all indices. Defaults to None.
            dry_run (bool, optional): If True, print request without sending.
                Defaults to False.

        Yields:
            ReadResponse: Response messages from the device containing counter data
        """
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        counter_entry = entity.counter_entry
        if counter_id is not None:
            counter_entry.counter_id = counter_id
        else:
            counter_entry.counter_id = 0
        if index is not None:
            counter_entry.index.index = index
        if dry_run:
            print("P4Runtime Read:", request)
        else:
            for response in self.client_stub.Read(request):
                yield response

    def WritePREEntry(self, pre_entry, dry_run=False):
        """Write a packet replication engine (PRE) entry to the device.

        Configures multicast group replication rules on the switch. These entries
        define how packets should be replicated to multiple output ports.

        Args:
            pre_entry (PacketReplicationEngineEntry): PRE configuration protobuf
            dry_run (bool, optional): If True, print request without sending.
                Defaults to False.

        Raises:
            grpc.RpcError: If the write operation fails on the device
        """
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        update.entity.packet_replication_engine_entry.CopyFrom(pre_entry)
        if dry_run:
            print("P4Runtime Write:", request)
        else:
            self.client_stub.Write(request)


class GrpcRequestLogger(grpc.UnaryUnaryClientInterceptor,
                        grpc.UnaryStreamClientInterceptor):
    """gRPC interceptor for logging all requests to a file.

    Captures all unary and streaming P4Runtime requests and logs them to a file
    with timestamps. Useful for debugging and auditing switch communications.

    Attributes:
        log_file (str): Path to the log file for storing request messages
    """

    def __init__(self, log_file):
        """Initialize the gRPC request logger.

        Args:
            log_file (str): Path to the file where requests will be logged.
                The file is cleared/created on initialization.
        """
        self.log_file = log_file
        with open(self.log_file, 'w') as f:
            # Clear content if it exists.
            f.write("")

    def log_message(self, method_name, body):
        """Log a single gRPC request message.

        Appends a timestamped message to the log file. Large messages exceeding
        MSG_LOG_MAX_LEN are truncated to avoid log file bloat.

        Args:
            method_name (str): Name of the gRPC method being called
            body: Request protobuf message to log
        """
        with open(self.log_file, 'a') as f:
            ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            msg = str(body)
            f.write("\n[%s] %s\n---\n" % (ts, method_name))
            if len(msg) < MSG_LOG_MAX_LEN:
                f.write(str(body))
            else:
                f.write("Message too long (%d bytes)! Skipping log...\n" % len(msg))
            f.write('---\n')

    def intercept_unary_unary(self, continuation, client_call_details, request):
        """Intercept unary-unary gRPC calls and log them.

        Args:
            continuation: Callback to invoke the actual RPC call
            client_call_details: Details about the RPC call being made
            request: Request protobuf message

        Returns:
            Response from the actual RPC call
        """
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)

    def intercept_unary_stream(self, continuation, client_call_details, request):
        """Intercept unary-stream gRPC calls and log them.

        Args:
            continuation: Callback to invoke the actual RPC call
            client_call_details: Details about the RPC call being made
            request: Request protobuf message

        Returns:
            Stream response from the actual RPC call
        """
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)


class IterableQueue(Queue):
    """Queue wrapper that supports iteration protocol.

    Allows a queue to be iterated using a for loop or iterator pattern.
    Iteration terminates when a sentinel value is encountered.

    Attributes:
        _sentinel: Special marker object signaling iteration end
    """
    _sentinel = object()

    def __iter__(self):
        """Enable iteration over queue items.

        Returns:
            Iterator that yields items from the queue until sentinel is encountered
        """
        return iter(self.get, self._sentinel)

    def close(self):
        """Signal end of iteration by putting sentinel value.

        Inserts the sentinel object into the queue, which terminates any active
        iteration when encountered.
        """
        self.put(self._sentinel)


def write_register(s1, p4info_helper, register_name, index, value):
    """
    Write a value to a P4 register at a specific index.

    :param p4info_helper: P4Info helper object
    :param sw: Switch connection
    :param register_name: Name of the register (e.g., "MyIngress.packet_counter")
    :param index: Index to write to
    :param value: Value to write
    """

    # Get register ID from p4info
    register_id = p4info_helper.get_id("registers", register_name)

    entry = p4runtime_pb2.RegisterEntry()
    entry.register_id = register_id
    entry.index.index = index
    entry.data.bitstring = value.to_bytes(
        4, byteorder='big')  # Assuming 32-bit integer data

    # Build write request
    request = p4runtime_pb2.WriteRequest()
    request.device_id = s1.device_id
    request.election_id.high = 0
    request.election_id.low = 1

    update = request.updates.add()
    update.type = p4runtime_pb2.Update.MODIFY
    update.entity.register_entry.CopyFrom(entry)

    # Send write request
    s1.client_stub.Write(request)


def read_register(p4info_helper, sw, register_name, index=None):
    """
    Read values from a P4 register.

    :param p4info_helper: P4Info helper object
    :param sw: Switch connection
    :param register_name: Name of the register (e.g., "MyIngress.packet_counter")
    :param index: Optional specific index to read, or None to read all entries
    :return: Dictionary of {index: value}
    """
    from util.lib.p4.v1 import p4runtime_pb2

    # Get register ID from p4info
    register_id = p4info_helper.get_id("registers", register_name)

    # Build read request
    request = p4runtime_pb2.ReadRequest()
    request.device_id = sw.device_id

    entity = request.entities.add()
    register_entry = entity.register_entry
    register_entry.register_id = register_id

    if index is not None:
        # Read specific index
        register_entry.index.index = index

    # Send request and parse response
    results = {}
    for response in sw.client_stub.Read(request):
        for entity in response.entities:
            if entity.HasField('register_entry'):
                idx = entity.register_entry.index.index
                # Assuming 32-bit integer data
                value = int.from_bytes(
                    entity.register_entry.data.bitstring,
                    byteorder='big'
                )
                results[idx] = value

    return results
