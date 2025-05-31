from pycfhelpers.common.parsers import parse_cf_v1_address
from pycfhelpers.node.logging import CFLog
import re, json, hashlib, base58, os
from pycfhelpers.node.net import CFNet
from response_helpers import send_json_response
from config import Config as c

log = CFLog()

class Utils:
    @staticmethod
    def validate_address(address):
        try:
            parse_cf_v1_address(address)
            return True
        except ValueError:
            log.error(f"{address} is not a valid CF address!")
            return False

    @staticmethod
    def validate_dna_name(name):
        if not re.match(r"^[a-zA-Z0-9\.\_\-]+$", name):
            log.error(f"Invalid DNA name: {name}")
            return False
        if len(name) < 3 or len(name) > 36:
            log.error("DNA name must be between 3 and 36 characters")
            return False
        log.notice("DNA name is valid")
        return True

    @staticmethod
    def validate_json_data(data):
        try:
            json_data = json.loads(data)
        except json.JSONDecodeError:
            return "Failed to decode JSON data!"
        action = json_data.get("action")
        if not action:
            return "Action is not provided!"
        if action == "add":
            name = json_data.get("name")
            address = json_data.get("wallet")
            if not name:
                return "Missing DNA name!"
            elif not Utils.validate_dna_name(name):
                return f"Invalid DNA name: {name}. DNA name must be between 3 and 36 characters long and contain only alphanumeric characters, hyphens, dots or underscores."
            elif name in c.load_config().get("DISALLOWED_NAMES"):
                return f"Invalid DNA name : {name}. Name is on disallowed list."
            if not address:
                return "Missing wallet address!"
            elif not Utils.validate_address(address):
                return f"Invalid wallet address: {address}"
            log.notice("Got valid data!")
            return False
        elif action == "update":
            return False

    @staticmethod
    def wallet_addr_to_dict(address):
        try:
            wallet = {}
            tuple = parse_cf_v1_address(address)
            if tuple:
                wallet["version"] = tuple[0]
                wallet["net_id"] = tuple[1]
                wallet["sign_id"] = tuple[2]
                wallet["public_hash"] = tuple[3]
                wallet["summary_hash"] = tuple[4]
                wallet["control_hash"] = tuple[5]
                return wallet
        except ValueError as e:
            log.error(f"Failed to parse wallet address: {e}")
            return None
        except Exception as e:
            log.error(f"Failed to parse wallet address: {e}")
            return None

    @staticmethod
    def is_tx_accepted(tx_hash, net=None):
        try:
            if net is None:
                net = CFNet("Backbone")
            else:
                net = CFNet(net)
            ledger = net.get_ledger()
            tx_by_hash = ledger.tx_by_hash(tx_hash)
            if tx_by_hash.accepted:
                return send_json_response("OK", None, 0)
            else:
                return send_json_response("NOK", "Transaction not accepted!", -1)
        except ValueError:
            log.error(f"Transaction with hash {tx_hash} not found!")
            return send_json_response("NOK", "Transaction not found!", -1)
        except Exception as e:
            log.error(f"This exploded: {e}")
            return send_json_response("NOK", "System exploded!", -1)

    @staticmethod
    def build_cf_address(version, net_id, sign_id, public_hash):
        net_id_bytes = net_id.to_bytes(8, byteorder="little")
        sign_id_bytes = sign_id.to_bytes(4, byteorder="little")
        raw_address = (
            version.to_bytes(1, "big")
            + net_id_bytes
            + sign_id_bytes
            + public_hash
        )
        hash = hashlib.sha3_256()
        hash.update(raw_address)
        control_hash = hash.digest()
        full_address = raw_address + control_hash
        return base58.b58encode(full_address).decode()

    @staticmethod
    def generate_wallet_addresses(sign_id, public_hash):
        net_ids = c.load_config().get("NET_IDS", [])
        return {
            net['name']: Utils.build_cf_address(1, int(net['id'], 16), sign_id, bytes.fromhex(public_hash))
            for net in net_ids
        }

    @staticmethod
    def get_current_script_directory():
        return os.path.dirname(os.path.abspath(__file__))