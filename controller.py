#!/usr/bin/env python3
# Copyright 2019 Belma Turkovic
# TU Delft Embedded and Networked Systems Group.
# NOTICE: THIS FILE IS BASED ON https://github.com/p4lang/tutorials/tree/master/exercises/p4runtime, BUT WAS MODIFIED UNDER COMPLIANCE
# WITH THE APACHE 2.0 LICENCE FROM THE ORIGINAL WORK.

# Packet parsing and manipulation
from scapy.all import (
    Ether,
    IP,
    TCP,
    UDP,
)

# Flask web framework for REST API
from flask import Flask, jsonify

# Standard library imports
import time
from threading import Thread
import os
import json
import argparse
import sys
from logging import log

# gRPC for P4Runtime communication
import grpc

# P4 Runtime utilities
import util.lib.p4_cli.helper as helper
from util.lib.p4_cli.switch import ShutdownAllSwitchConnections
import util.lib.p4_cli.bmv2 as bmv2
from util.lib.p4_cli.convert import encodeNum, decode
# Add util directories to Python path to enable imports of P4Runtime libraries
# This allows us to import custom P4 helper modules from the util directory
sys.path.append(os.path.join(os.path.dirname(
    os.path.abspath(__file__)), "util/"))
sys.path.append(os.path.join(os.path.dirname(
    os.path.abspath(__file__)), "."))
sys.path.append(os.path.join(os.path.dirname(
    os.path.abspath(__file__)), "util/lib/"))

# Global state: stores active switch controllers indexed by switch_id
controllers = {}

# Global state: stores all controller threads for packet processing
threads = []


def printGrpcError(e):
    """
    Print detailed gRPC error information for debugging.

    Args:
        e: gRPC RpcError exception containing error details

    Outputs error message, status code, and traceback location to stdout.
    """
    print("gRPC Error:", e.details(), end="")
    status_code = e.code()
    print("(%s)" % status_code.name, end="")
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))


app = Flask(__name__)


@app.route('/api/status', methods=['GET'])
def get_status():
    """Simple health endpoint to verify controller/API are running."""
    return jsonify({
        'status': 'Controller is running',
        'switches_connected': len(controllers)
    })


@app.route('/api/switches', methods=['GET'])
def get_switches():
    """
    Returns information about all connected switches.

    Returns:
        JSON array containing switch information (switch_id, address, device_id)
        or 404 error if no switches are connected.
    """
    global controllers
    resp = []

    for switch_id, controller in controllers.items():
        resp.append({
            'switch_id': switch_id,
            'address': controller.address,
            'device_id': controller.device_id
        })

    if len(resp) == 0:
        return jsonify({
            'error': f'Switch {switch_id} not found'
        }), 404

    return jsonify(resp)


def run_http_server(port=5000):
    """
    Run the Flask HTTP server in a separate thread.
    """
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

# REST API and helper 

def s1():
    return controllers["s1"]

@app.route('/api/port-forward/add/<internal_ip>/<int:internal_port>/<int:external_port>', methods=['GET'])
def api_port_forward_add(internal_ip, internal_port, external_port):
    try:
        s1().add_port_forward_rule(internal_ip, internal_port, external_port)
        return jsonify({
            "status": "ok",
            "internal_ip" : internal_ip,
            "internal_port": internal_port,
            "external_port": external_port
        })
    except KeyError:
        return jsonify({"error" : "S1 not connected"})
    except Exception as e:
        return jsonify({"error" : str(e)}), 500

@app.route('/api/port-forward/list', methods=['GET'])
def api_port_forward_list():
    try:
        return jsonify(s1().list_port_forward_rules())
    except KeyError:
        return jsonify({"error" : "S1 not connected"})
    except Exception as e:
        return jsonify({"error" : str(e)}), 500

@app.route('/api/nat/list', methods=['GET'])
def api_nat_list():
    try:
        return jsonify(s1().list_nat_translations())
    except KeyError:
        return jsonify({"error" : "S1 not connected"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

class SwitchController:
    """
    Base class for switch controller with packet learning logic.

    This class manages the connection to a P4 programmable switch via P4Runtime,
    handles switch configuration, and processes incoming packets.
    """

    def __init__(self, switch_id, address, device_id, p4info_helper, config):
        """
        Initialize the switch controller.

        Args:
            switch_id: Unique identifier for the switch (e.g., 's1', 's2')
            address: gRPC server address for P4Runtime (e.g., '127.0.0.1:50001')
            device_id: Numeric device identifier for the switch
            p4info_helper: Helper object for P4Info file parsing
            config: Configuration dictionary loaded from JSON
        """
        self.switch_id = switch_id
        self.address = address
        self.device_id = device_id
        self.p4info_helper = p4info_helper
        self.config = config
        self.switch = None  # Will hold the BMv2 switch connection
        self.smac = []  # Source MAC address learning table

    def connect(self):
        """Establish connection to the switch."""
        self.switch = bmv2.Bmv2SwitchConnection(
            name=self.switch_id,
            address=self.address,
            device_id=self.device_id,
            proto_dump_file=f"{self.switch_id}-p4runtime.log",
        )
        return self.switch

    def read_table(self, table_name):
        """
        This method reads all entries from a specified table on the switch and decodes them into a human-readable format.

        Args:
            table_name: Name of the table to read entries from
        Returns:
            A list of dictionaries, each representing a table entry with fields:
            - is_default: Boolean indicating if this is the default entry
            - priority: Priority of the entry (if applicable)
            - matches: Dictionary of match field names and their decoded values
            - action: Dictionary containing action name and parameters (if applicable)
        """
        table_id = self.p4info_helper.get_tables_id(table_name)
        entries = []
        for response in self.switch.ReadTableEntries(table_id=table_id):
            for entity in response.entities:
                te = entity.table_entry
                entry = {
                    "is_default": te.is_default_action,
                    "priority": te.priority if te.priority else None,
                    "matches": {},
                    "action": None,
                }

                # matches
                for mf in te.match:
                    # get human name for the match field
                    try:
                        mname = self.p4info_helper.get_match_field_name(
                            table_name, mf.field_id)
                    except Exception:
                        mname = f"field_id_{mf.field_id}"
                    # decode value via the helper
                    mval = self.p4info_helper.get_match_field_value(mf)
                    entry["matches"][mname] = decode(
                        mval, self.p4info_helper.get_match_field_bitwidth(table_name, mf.field_id))

                # action + params
                if te.action and te.action.action.action_id != 0:
                    aid = te.action.action.action_id
                    aname = self.p4info_helper.get_actions_name(aid)
                    params = {}
                    for p in te.action.action.params:
                        try:
                            pname = self.p4info_helper.get_action_param_name(
                                aname, p.param_id)
                        except Exception:
                            pname = f"param_{p.param_id}"
                        params[pname] = decode(p.value, self.p4info_helper.get_action_param_bitwidth(
                            aname, p.param_id))  # raw bytes; decode as needed
                    entry["action"] = {"name": aname, "params": params}

                entries.append(entry)
        return entries

    def configure(self):
        """
        Configure the switch with initial table entries and runtime settings.

        This method can be overridden by subclasses to install initial table entries,
        create multicast groups, or perform other switch-specific configuration.
        By default, no configuration is performed.
        """
        return

    def setup(self, bmv2_file_path):
        """
        Set up the switch with P4 program and configuration.

        Args:
            bmv2_file_path: Path to the compiled P4 program (BMv2 JSON file)

        Raises:
            grpc.RpcError: If connection fails or election ID is already in use
        """
        # Establish gRPC connection and set master arbitration update
        # This ensures this controller has primary control of the switch
        try:
            MasterArbitrationUpdate = self.switch.MasterArbitrationUpdate()
            print(
                f"[{self.switch_id}] MasterArbitrationUpdate: {MasterArbitrationUpdate}")
            if MasterArbitrationUpdate is None:
                print(f"[{self.switch_id}] Failed to establish the connection")
        except grpc.RpcError as e:
            # Handle the case where another controller is already connected
            if "already used" in str(e):
                print(
                    f"[{self.switch_id}] Error: Election ID already in use by another controller")
                print(
                    "Try: 1) Wait and retry  2) Restart the switch  3) Kill competing processes")
                raise
            else:
                raise

        # Install the P4 program on the switch
        # This loads the compiled P4 program and P4Info metadata onto the switch
        try:
            self.switch.SetForwardingPipelineConfig(
                p4info=self.p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path
            )
            print(
                f"[{self.switch_id}] Installed P4 Program using SetForwardingPipelineConfig")
        except Exception as e:
            print(f"[{self.switch_id}] Forwarding Pipeline added.")
            print(e)

    def run(self):
        """
        Main packet processing loop - continuously listens for packets from the switch.

        This method runs indefinitely, receiving PacketIn messages from the switch
        via the P4Runtime stream channel and processing them. Can be overridden
        by subclasses to implement custom packet handling logic.
        """
        print(f"[{self.switch_id}] Starting packet processing loop...")
        while True:
            try:
                print(f"[{self.switch_id}] Listening for packets...")
                # Block and wait for a PacketIn message from the switch
                msg = self.switch.PacketIn()
                print(f"[{self.switch_id}] Got stream message")

                # No message received - sleep briefly and continue waiting
                if msg is None:
                    time.sleep(0.1)
                    continue

                # If the stream contains an error, print detailed error information
                # This helps diagnose issues with PacketOut, digest acknowledgments, etc.
                try:
                    if msg.HasField("error"):
                        err = msg.error
                        print(
                            f"[{self.switch_id}] StreamError received: canonical_code={err.canonical_code} code={err.code} space='{err.space}' message='{err.message}'")
                        # Print any specific error details present
                        try:
                            if err.HasField('packet_out'):
                                print(
                                    f"[{self.switch_id}] PacketOutError: {err.packet_out}")
                            elif err.HasField('digest_list_ack'):
                                print(
                                    f"[{self.switch_id}] DigestListAckError: {err.digest_list_ack}")
                            elif err.HasField('other'):
                                print(
                                    f"[{self.switch_id}] StreamOtherError: {err.other}")
                        except Exception:
                            # Safe fallback if detail fields are not present or accessible
                            pass
                        continue
                except Exception:
                    # If HasField isn't available for some message types, fall back
                    pass

                # Normal packet-in handling - process packets sent to controller
                try:
                    if msg.HasField("digest"):
                        self.handle_digest(msg.digest)
                    elif msg.HasField("packet"):
                        self.handle_packet(msg)
                    else:
                        print(
                            f"[{self.switch_id}] Unhandled stream message: {msg}")
                except Exception:
                    # If message doesn't support HasField or structure differs, try to handle directly
                    self.handle_packet(msg)

            except grpc.RpcError as e:
                printGrpcError(e)
                break
            except Exception as e:
                print(f"[{self.switch_id}] Exception in run loop: {e}")
                break

    def handle_packet(self, packetin):
        """
        Handle incoming packet from the switch.

        Args:
            packetin: P4Runtime PacketIn message containing packet data and metadata

        This method can be overridden by subclasses to implement custom packet
        processing logic. By default, it simply logs the packet details.
        """
        print(f"[{self.switch_id}] PACKET IN received: {str(packetin)}")
        # Extract the raw packet payload
        data = packetin.packet.payload
        # Parse the Ethernet frame using Scapy
        a = Ether(bytes(data))
        print(f"[{self.switch_id}] Received packet: {a.summary()}")

    def handle_digest(self, digest):
        """
        Handle incoming digest messages from the switch
        """
        print(f"[{self.switch_id}] DIGEST received: {str(digest)}")


class NATController(SwitchController):
    """
    Controller for NAT (Network Address Translation) switch.

    This controller manages a switch performing basic NAT functionality,
    translating IP addresses for packets traversing the network boundary.
    """

    def configure(self):
        """
        Install NAT-specific configuration and table entries.

        Loads NAT translation rules from the configuration file and installs
        them into the switch's forwarding tables.
        """
        print(f"[{self.switch_id}] Installing NAT configuration...")
        print(self.config)
        # Add logic to install NAT table entries from config
        for table_entry in self.config.get("nat_table_entries", []):
            entry = self.p4info_helper.buildTableEntry(
                table_name=table_entry["table"], 
                match_fields=table_entry.get("matches", {}), 
                action_name=table_entry.get("action_name"), 
                action_params=table_entry.get("action_params", {}), 
                priority=table_entry.get("priority", 0), 
                default_action=table_entry.get("default_action", False)) 
            self.switch.WriteTableEntry(entry) 
            print(f"[{self.switch_id}] Installed NAT table entry: {entry}")
        return 


class PATController(SwitchController):
    """
    Controller for PAT (Port Address Translation) switch.

    This controller manages a switch performing port-based NAT (PAT),
    translating both IP addresses and port numbers for outbound connections.
    """

    def configure(self):
        # Install PAT-specific configuration and table entries from the config file
        self.public_ip = None
        self.learned = set()

        for table_entry in self.config.get("pat_table_entries", []):

            entry = self.p4info_helper.buildTableEntry(
                table_name=table_entry["table"], 
                match_fields=table_entry.get("matches", {}), 
                action_name=table_entry.get("action_name"), 
                action_params=table_entry.get("action_params", {}), 
                priority=table_entry.get("priority", 0), 
                default_action=table_entry.get("default_action", False)) 
            self.switch.WriteTableEntry(entry) 

            if (table_entry.get("table") == "MyIngress.pat_out_cfg"and table_entry.get("action_name") == "MyIngress.pat_out"):
                self.public_ip = table_entry.get("action_params", {}).get("public_ip")

        if self.public_ip is None:
            raise RuntimeError("Missing public_ip: expected pat_out_cfg in s1-runtime.json")
        
    def packet_out(self, payload, egress_port):
        try: self.switch.PacketOut(payload=payload, metadata={"egress_port": egress_port})
        except Exception as e:
            print(f"[{self.switch_id}] Error sending PacketOut: {e}")

    def handle_packet(self, packetin):
        """
        Custom packet handling incoming packet from the switch.

        Args:
            packetin: P4Runtime PacketIn message containing packet data and metadata

        This method can be overridden by subclasses to implement custom packet
        processing logic. By default, it simply logs the packet details.
        """
        print(f"[{self.switch_id}] PACKET IN received: {str(packetin)}")
        # Extract the raw packet payload
        data = packetin.packet.payload
        # Parse the Ethernet frame using Scapy
        a = Ether(bytes(data))
        print(f"[{self.switch_id}] Received packet: {a.summary()}")

        if IP not in a:
            return
        
        ip = a[IP]
        proto = int(ip.proto)
        if proto == 6 and TCP in a:
            l4port = int(a[TCP].sport)
        elif proto == 17 and UDP in a:
            l4port = int(a[UDP].sport)
        else:
            return
        
        private_ip = ip.src
        if self.public_ip is None:
            return
        
        key = (private_ip, proto, l4port)
        if key in self.learned:
            return
        self.learned.add(key)

        # Mark outbound flow as learned 
        learn_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.learn_table",
            match_fields={
                "hdr.ipv4.srcAddr": private_ip,
                "meta.l4Proto": proto,
                "meta.l4Port": l4port
            },
            action_name= "MyIngress.mark_learned",
            action_params={}
        )
        self.switch.WriteTableEntry(learn_entry)

        # Inbound return traffic 
        pat_in_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.pat_in_table",
            match_fields={
                "hdr.ipv4.dstAddr": self.public_ip,
                "meta.l4Proto": proto,
                "meta.l4Port": l4port
            },
            action_name= "MyIngress.pat_in",
            action_params={
                "private_ip": private_ip
            }
        )
        self.switch.WriteTableEntry(pat_in_entry)
        
        # Send the packet out to the egress port
        egress_port = 2
        md = {1: int(egress_port).to_bytes(2, byteorder= "big")}
        pkt_out = self.p4info_helper.buildPacketOut(payload= data, metadata= md)
        self.switch.PacketOut(pkt_out)

    def add_port_forward_rule(self, internal_ip, internal_port, external_port):
        # Inbound
        entry = self.p4info_helper.buildTableEntry(
            table_name = "MyIngress.port_fwd_table",
            match_fields = {
                "hdr.ipv4.dstAddr" : self.public_ip,
                "meta.l4Proto": 6,
                "meta.l4Port": int(external_port)
            },
            action_name="MyIngress.port_fwd",
            action_params={
                "internal_ip": internal_ip,
                "internal_port" : int(internal_port)
            }
        )
        self.switch.WriteTableEntry(entry)

        # Outbound
        rev_entry = self.p4info_helper.buildTableEntry(
            table_name = "MyIngress.port_fwd_rev_table",
            match_fields = {
                "hdr.ipv4.srcAddr" : internal_ip,
                "meta.l4Proto": 6,
                "meta.l4Port": int(internal_port)
            },
            action_name="MyIngress.port_fwd_rev",
            action_params={
                "external_port" : int(external_port)
            }
        )
        self.switch.WriteTableEntry(rev_entry)

    
    def list_port_forward_rules(self):
        rows = self.read_table("MyIngress.port_fwd_table")
        out = []
        for row in rows:
            if row["is_default"] or row["action"] is None:
                continue
            match = row["matches"]
            action = row["action"]["params"]
            out.append({
                "internal_ip" : action.get("internal_ip"),
                "internal_port" : action.get("internal_port"),
                "external_port": match.get("meta.l4Port")
            })
        return out
    
    def list_nat_translations(self):
        rows = self.read_table("MyIngress.pat_in_table")
        out = []
        for row in rows:
            if row["is_default"] or row["action"] is None:
                continue
            match = row["matches"]
            action = row["action"]["params"]
            proto = match.get("meta.l4Proto")
            out.append({
                "private_ip" : action.get("private_ip"),
                "private_port" : match.get("meta.l4Port"),
                "public_ip": match.get("hdr.ipv4.dstAddr"),
                "public_port": match.get("meta.l4Port"),
                "protocol" : "TCP" if proto == 6 else ("UDP"if proto == 17 else str(proto)) 
            })
        return out

def main(switches_config=None):
    """
    Main controller function that supports multiple switches.

    Args:
        switches_config: List of switch configurations, each containing:
            - switch_id: Identifier for the switch (e.g., 's1', 's2')
            - address: gRPC address (e.g., '127.0.0.1:50001')
            - device_id: Device ID for the switch
            - config_file: Path to runtime config JSON file
            - controller_class: Class to use for this switch (Switch1Controller or Switch2Controller)
    """
    global controllers, threads

    # Default to single switch if no config provided (backward compatibility)
    if switches_config is None or len(switches_config) == 0:
        log.info("Configuration file is empty or not provided, exiting....")
        sys.exit(1)

    # Start HTTP server in a separate thread
    http_thread = Thread(target=run_http_server, args=(8080,), daemon=True)
    http_thread.start()
    print("HTTP server started on http://0.0.0.0:8080")

    try:
        # Create and setup controllers for each switch in the configuration
        # Each switch gets its own controller instance and packet processing thread
        for switch_cfg in switches_config:
            switch_id = switch_cfg['switch_id']
            config_file_path = switch_cfg['config_file']
            bmv2_file_path = switch_cfg['p4file']

            if not os.path.exists(config_file_path):
                print(
                    f"Runtime config file {config_file_path} not found for {switch_id}!")
                continue

            # Load runtime configuration (e.g., table entries, translation rules)
            config = json.load(open(config_file_path))

            # Validate that required P4 files exist before proceeding
            if not os.path.exists(switch_cfg['p4info']):
                print(
                    f"P4Info file {switch_cfg['p4info']} not found for {switch_id}!")
                continue

            if not os.path.exists(switch_cfg['p4file']):
                print(
                    f"BMv2 JSON file {switch_cfg['p4file']} not found for {switch_id}!")
                continue

            # Create controller instance using the appropriate class based on switch type
            # This allows different switches to have specialized packet handling logic
            if switch_cfg.get('controller_type', "") == 'pat':
                controller_class = PATController
            elif switch_cfg.get('controller_type', "") == 'nat':
                controller_class = NATController
            else:
                controller_class = SwitchController

            # Instantiate the controller with all necessary configuration
            controller = controller_class(
                switch_id=switch_id,
                address=switch_cfg['address'],
                device_id=switch_cfg['device_id'],
                p4info_helper=helper.P4InfoHelper(switch_cfg['p4info']),
                config=config
            )

            # Establish connection, load P4 program, and apply initial configuration
            controller.connect()
            controller.setup(bmv2_file_path)
            controller.configure()

            # Store controller in global registry for API access
            controllers[switch_id] = controller

            # Create a daemon thread for this switch's packet processing loop
            # Daemon threads will automatically terminate when the main program exits
            thread = Thread(target=controller.run, daemon=True)
            thread.start()
            threads.append(thread)
            print(f"[{switch_id}] Controller thread started")

        # Wait for all threads (they run indefinitely until interrupted)
        # This keeps the main thread alive while controllers process packets
        for thread in threads:
            thread.join()

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)
    finally:
        # Ensure all switch connections are properly closed on exit
        ShutdownAllSwitchConnections()


if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="SCC333 P4Runtime Controller")
    parser.add_argument(
        "--config",
        help="Path to controller configuration JSON file (default: controller.json)",
        type=str,
        action="store",
        required=False,
        default="controller.json",
    )

    args = parser.parse_args()

    # Load switch configuration from JSON file
    # This file defines which switches to connect to and their parameters
    switches_config = json.load(open(args.config))

    # Start the main controller with the loaded configuration
    main(switches_config=switches_config)
