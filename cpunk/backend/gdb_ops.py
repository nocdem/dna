from datetime import datetime, timedelta, timezone
from response_helpers import send_json_response
from utils import Utils as u
from config import Config
from pycfhelpers.node.logging import CFLog
from pycfhelpers.node.gdb import CFGDBGroup
from pycfhelpers.node.crypto import CFGUUID
from time import sleep
import json, threading, traceback, copy, os

thread_lock = threading.Lock()

class GlobalDBOps:
    def __init__(self):
        self.gdb_group = CFGDBGroup(Config.GDB_GROUP_TEST if Config.TEST_MODE else Config.GDB_GROUP_PROD)
        self.log = CFLog()
        threading.Thread(target=self.remove_expired_gdb_entries, daemon=True).start()
        threading.Thread(target=self.backup_dna_data, daemon=True).start()

    def _get_public_hash(self, data):
        wallet = u.wallet_addr_to_dict(data.get("wallet"))
        if wallet:
            return wallet["public_hash"].hex(), wallet["sign_id"]
        self.log.error("Failed to parse wallet address!")
        return None, None

    def _is_name_taken(self, name, all_data, exclude_hash=None):
        for key, value in all_data.items():
            if key != exclude_hash:
                registered_names = value.get("registered_names", {})
                if name in registered_names:
                    return True
        return False

    def _get_all_gdb_data(self):
        result_dict = {}
        for key, value in self.gdb_group.items():
            try:
                result_dict[key] = json.loads(value.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                self.log.error(f"Error decoding data for key {key}: {e}")
                self.log.error(traceback.format_exc())
        return result_dict

    def write_gdb_data(self, data):
        try:
            self.log.notice(f"Received data: {data}")
            name = data.get("name", "").lower()
            tx_hash = data.get("tx_hash")
            if not name:
                return send_json_response("NOK", "Name is missing from data!", -1)
            public_hash, sign_id = self._get_public_hash(data)
            self.log.notice(f"Got public hash {public_hash} and sign_id {sign_id}")
            if not public_hash:
                return send_json_response("NOK", "Failed to parse wallet address!", -1)

            existing_entry = self.gdb_group.get(public_hash)
            all_data = self._get_all_gdb_data()

            if existing_entry:
                self.log.notice(existing_entry)
                existing_entry_json = json.loads(existing_entry.decode("utf-8"))
                if name in existing_entry_json.get("registered_names", {}):
                    return send_json_response("NOK", f"You have already registered {name}, use update method!", -1)
                self.log.notice("Data already exists in GlobalDB, updating...")
                return self.update_gdb_data_old_name(data)
            if self._is_name_taken(name, all_data, exclude_hash=public_hash):
                self.log.error(f"Name '{name}' is already taken.")
                return send_json_response("NOK", f"Name '{name}' is already taken!", -1)

            data_to_write = {
                    "public_hash": public_hash,
                    "guuid": str(CFGUUID.generate()).lower(),
                    "sign_id": sign_id,
                    "registered_names": {
                        name: {
                            "created_at": datetime.now(timezone.utc).isoformat(),
                            "expires_on": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
                            "tx_hash": tx_hash
                        }
                    },
                    "socials": {
                        "telegram": {
                            "profile": ""
                        },
                        "x": {
                            "profile": ""
                        },
                        "facebook": {
                            "profile": ""
                        },
                        "instagram": {
                            "profile": ""
                        }
                    },
                    "bio": "",
                    "dinosaur_wallets": {"BTC": "", "ETH": "", "SOL": "", "QEVM": "" },
                    "nft_images": [],
                    "profile_picture": "",
                    "delegations": [],
                    "messages": []
                }
            self.gdb_group.set(
                public_hash,
                json.dumps(data_to_write).encode("utf-8")
            )
            self.log.notice(f"Wrote {public_hash} to GlobalDB")
            return send_json_response("OK", "Data was written to GlobalDB!", 0, response_data=data_to_write)
        except Exception as e:
            self.log.error(f"Error: {e}")
            self.log.error(traceback.format_exc())
            return send_json_response("NOK", "Failed to write data to GlobalDB", -1)

    def update_gdb_data_old_name(self, data):
        try:
            public_hash, _ = self._get_public_hash(data)
            if not public_hash:
                return send_json_response("NOK", "Failed to parse wallet address!", -1)

            existing_data = self.gdb_group.get(public_hash)
            if not existing_data:
                self.log.error(f"No existing data found for {public_hash}")
                return send_json_response("NOK", f"No existing data found for {public_hash}", -1)

            existing_data = json.loads(existing_data.decode("utf-8"))
            original_data = copy.deepcopy(existing_data)

            if data.get("guuid"):
                return send_json_response("NOK", "Changing GUUID is not possible!", -1) # Make sure that GUUID is always the same.

            new_name = data.get("name", "").lower()
            if new_name:
                all_data = self._get_all_gdb_data()
                if self._is_name_taken(new_name, all_data, exclude_hash=public_hash):
                    self.log.error(f"Name '{new_name}' is already taken.")
                    return send_json_response("NOK", f"Name '{new_name}' is already taken!", -1)

                existing_data.setdefault("registered_names", {})

                if new_name in existing_data["registered_names"]:
                    self.log.notice(f"Name '{new_name}' already exists, extending expiration date.")
                    current_expiration = existing_data["registered_names"][new_name]["expires_on"]
                    new_expiration_date = datetime.fromisoformat(current_expiration) + timedelta(days=365)
                    existing_data["registered_names"][new_name]["expires_on"] = new_expiration_date.isoformat()
                    if "tx_hash" in data:
                        existing_data["registered_names"][new_name]["tx_hash"] = data["tx_hash"]
                else:
                    existing_data["registered_names"][new_name] = {
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "expires_on": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
                        "tx_hash": data.get("tx_hash", "")
                    }

            if "socials" in data:
                existing_data.setdefault("socials", {})
                for platform, details in data["socials"].items():
                    existing_data["socials"].setdefault(platform, {"profile": ""})
                    if "profile" in details:
                        existing_data["socials"][platform]["profile"] = details["profile"]

            if "nft_images" in data:
                existing_data.setdefault("nft_images", [])
                existing_data["nft_images"].extend(data["nft_images"])

            if "bio" in data:
                existing_data["bio"] = data["bio"]

            if "profile_picture" in data:
                existing_data["profile_picture"] = data["profile_picture"]

            if "dinosaur_wallets" in data:
                existing_data.setdefault("dinosaur_wallets", {})
                for network, address in data["dinosaur_wallets"].items():
                    existing_data["dinosaur_wallets"][network] = address

            if "delegations" in data:
                existing_data.setdefault("delegations", [])
                if not data["delegations"]:
                    existing_data["delegations"] = []
                else:
                    for delegation in data["delegations"]:
                        delegation.setdefault("delegation_time", datetime.now(timezone.utc).isoformat())
                        existing_data["delegations"].append(delegation)

            if "messages" in data:
                existing_data.setdefault("messages", [])
                if not data["messages"]:
                    existing_data["messages"] = []
                else:
                    for message in data["messages"]:
                        message.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
                        existing_data["messages"].append(message)

            if existing_data != original_data:
                existing_data["modified_at"] = datetime.now(timezone.utc).isoformat()
                self.gdb_group.set(public_hash, json.dumps(existing_data).encode("utf-8"))
                self.log.notice(f"Updated {public_hash} in GlobalDB")

                existing_data["public_hash"] = public_hash
                return send_json_response("OK", f"Updated {public_hash} in GlobalDB", 0, response_data=existing_data)
            else:
                return send_json_response("OK", "No changes detected, data was not updated.", 0, response_data=existing_data)

        except Exception as e:
            self.log.error(f"Failed to update GlobalDB: {e}")
            self.log.error(traceback.format_exc())
            return send_json_response("NOK", "Failed to update GlobalDB", -1)

    def gdb_lookup(self, lookup, by_telegram_name=False, by_order_hash=False, as_list=False):
        try:
            all_data = self._get_all_gdb_data()
            if lookup == "all_delegations":
                all_delegations = []
                for public_hash, parsed_data in all_data.items():
                    delegations = parsed_data.get("delegations", [])
                    if not delegations:
                        continue
                    for delegation in delegations:
                        enriched = delegation.copy()
                        enriched["public_hash"] = public_hash
                        enriched["sign_id"] = parsed_data.get("sign_id")
                        enriched["registered_names"] = parsed_data.get("registered_names", [])
                        if "guuid" in parsed_data:
                            del parsed_data["guuid"]
                        all_delegations.append(enriched)
                return send_json_response(status_code=0, response_data=all_delegations)

            if by_telegram_name:
                for public_hash, parsed_data in all_data.items():
                    telegram_profile = parsed_data.get("socials", {}).get("telegram", {}).get("profile", "").lower()
                    if telegram_profile and telegram_profile == lookup.lower():
                        parsed_data["wallet_addresses"] = u.generate_wallet_addresses(parsed_data["sign_id"], public_hash)
                        if parsed_data.get("guuid", ""):
                            del parsed_data["guuid"]
                        return send_json_response(
                            status_code=0,
                            response_data=parsed_data
                        )
                return send_json_response("NOK", f"Telegram username {lookup} not found", -1)

            if by_order_hash:
                for public_hash, parsed_data in all_data.items():
                    delegations = parsed_data.get("delegations", [])
                    for delegation in delegations:
                        if delegation.get("order_hash", "") == lookup:
                            parsed_data["wallet_addresses"] = u.generate_wallet_addresses(parsed_data["sign_id"], public_hash)
                            parsed_data.pop("guuid", None)
                            return send_json_response(status_code=0, response_data=parsed_data)
                return send_json_response("NOK", f"Order hash {lookup} not found", -1)

            if not u.validate_address(lookup):
                all_results = []
                for public_hash, parsed_data in all_data.items():
                    if "registered_names" in parsed_data:
                        if as_list:
                            matched_names = [
                                name for name in parsed_data["registered_names"]
                                if lookup.lower() in name.lower()
                            ]
                        else:
                            matched_names = [
                                name for name in parsed_data["registered_names"]
                                if lookup.lower() == name.lower()
                            ]
                        if matched_names:
                            if as_list:
                                all_results.extend(matched_names)
                            else:
                                if parsed_data.get("guuid", ""):
                                    del parsed_data["guuid"]
                                parsed_data["wallet_addresses"] = u.generate_wallet_addresses(parsed_data["sign_id"], public_hash)
                                return send_json_response(status_code=0, response_data=parsed_data)

                if as_list and all_results:
                    return send_json_response(status_code=0, response_data=all_results)

                return send_json_response("NOK", f"Name or GUUID '{lookup}' not found", -1)

            public_hash, _ = self._get_public_hash({"wallet": lookup})
            if not public_hash:
                return send_json_response("NOK", "Failed to parse wallet address!", -1)

            info = self.gdb_group.get(public_hash)
            if info:
                info = json.loads(info.decode("utf-8"))
                if "registered_names" in info:
                    info["wallet_addresses"] = u.generate_wallet_addresses(info["sign_id"], public_hash)
                    if info.get("guuid", ""):
                        del info["guuid"]
                    return send_json_response(status_code=0, response_data=info)

            return send_json_response("NOK", f"No wallet address found for {lookup}", -1)

        except Exception as e:
            self.log.error(f"Error fetching data for {lookup}: {e}")
            self.log.error(traceback.format_exc())
            return send_json_response("NOK", f"Error fetching data for {lookup}", -1)

    def remove_expired_gdb_entries(self):
        while True:
            try:
                current_time = datetime.now(timezone.utc)
                all_data = self._get_all_gdb_data()

                if all_data:
                    for key, value in all_data.items():
                        if "registered_names" in value:
                            expired_keys = []
                            for name, data in value["registered_names"].items():
                                try:
                                    expires_on = datetime.fromisoformat(data["expires_on"])
                                    if expires_on < current_time:
                                        expired_keys.append(name)
                                        self.log.notice(f"Found expired registered name: {name}")

                                except ValueError:
                                    self.log.error(f"Invalid datetime format for {name}: {data['expires_on']}")

                            for expired_key in expired_keys:
                                del value["registered_names"][expired_key]
                                self.log.notice(f"Removed expired registered name: {expired_key}")

                            if expired_keys:
                                    self.gdb_group.set(key, json.dumps(value).encode("utf-8"))
                                    self.log.notice(f"Updated entry {key} to remove expired registered names.")
                sleep(1)
            except Exception as e:
                self.log.error(f"Failed to remove expired entries: {e}")
                self.log.error(traceback.format_exc())

    def backup_dna_data(self):
        try:
            curr_path = os.path.dirname(os.path.abspath(__file__))
            backup_dir = os.path.join(curr_path, "backups")
            os.makedirs(backup_dir, exist_ok=True)
            last_backup = None
            backup_files = sorted(
                [f for f in os.listdir(backup_dir) if f.startswith("backup_")],
                key=lambda x: os.path.getmtime(os.path.join(backup_dir, x)),
            )

            if backup_files:
                last_backup_file = os.path.join(backup_dir, backup_files[-1])
                with open(last_backup_file, "r") as f:
                    last_backup = f.read()

            while True:
                curr_time = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                backup_file = os.path.join(backup_dir, f"backup_{curr_time}.json")
                all_data = self._get_all_gdb_data()
                if all_data:
                    new_backup = json.dumps(all_data, indent=2)
                    if new_backup != last_backup:
                        self.log.notice("Data changed, creating backup")
                        with open(backup_file, "w") as f:
                            f.write(new_backup)
                        last_backup = new_backup
                        self.log.notice("Backup created!")
                    backup_files.append(backup_file)
                    if len(backup_files) > 100:
                        oldest = backup_files.pop(0)
                        os.remove(oldest)
                        self.log.notice(f"Deleted old backup: {oldest}")
                sleep(600)

        except Exception as e:
            self.log.error(f"Failed to run backup: {e}")
            self.log.error(traceback.format_exc())

    def restore_dna_data(self, data):
        try:
            for key, value in data.items():
                self.gdb_group.set(key, json.dumps(value).encode("utf-8"))
            self.log.notice("Data restoration complete.")
        except Exception as e:
            self.log.error(f"Failed to restore data: {e}")
            self.log.error(traceback.format_exc())