from pycfhelpers.node.logging import CFLog
from pycfhelpers.node.http.simple import CFSimpleHTTPServer, CFSimpleHTTPRequestHandler
import json, os

log = CFLog()

class Config:
    TEST_MODE = False
    PLUGIN_NAME = "cpunk-gdb-server"
    URL = "cpunk_gdb"
    GDB_GROUP_PROD = "cpunk.dna"
    GDB_GROUP_TEST = "local.dna"

    @staticmethod
    def get_config_file():
        from utils import Utils as u
        return os.path.join(u.get_current_script_directory(), "config.json")

    @classmethod
    def load_config(cls):
        try:
            with open(cls.get_config_file(), "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            log.error("Configuration file not found!")
            return {}

    @classmethod
    def save_config(cls, config_data):
        with open(cls.get_config_file(), "w") as f:
            log.notice(config_data)
            json.dump(config_data, f, indent=4)
