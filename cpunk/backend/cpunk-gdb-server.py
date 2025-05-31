from handlers import request_handler, gdb_ops
from pycfhelpers.node.http.simple import CFSimpleHTTPServer, CFSimpleHTTPRequestHandler
from pycfhelpers.node.logging import CFLog
from pycfhelpers.node.cli import ReplyObject, CFCliCommand
import threading, os, json, traceback
from config import Config

log = CFLog()

def restore_dna_data_from_file(index, reply_object: ReplyObject):
    if index is None:
        reply_object.reply("Please provide the index of the backup.")
        return
    try:
        curr_path = os.path.dirname(os.path.abspath(__file__))
        backup_dir = os.path.join(curr_path, "backups")
        backup_files = sorted(
            [f for f in os.listdir(backup_dir) if f.startswith("backup_")],
            key=lambda x: os.path.getmtime(os.path.join(backup_dir, x)),
            reverse=True,
        )
        if not backup_files:
            reply_object.reply("No backups found.")
            return
        try:
            index = int(index)
        except ValueError:
            reply_object.reply("Invalid value!")
            return
        if index < 0 or index >= len(backup_files):
            reply_object.reply(f"Invalid index. Available range: 0-{len(backup_files) - 1}")
            return
        backup_file = os.path.join(backup_dir, backup_files[index])
        with open(backup_file, "r") as f:
            data = json.load(f)
        gdb_ops.restore_dna_data(data)
        reply_object.reply(f"Restored backup from {backup_file}")

    except Exception as e:
        reply_object.reply(f"Failed to restore backup: {e}")
        log.error(traceback.format_exc())

def http_server():
    try:
        handler = CFSimpleHTTPRequestHandler(methods=["POST", "GET"], handler=request_handler)
        CFSimpleHTTPServer().register_uri_handler(uri=f"/{Config.URL}", handler=handler)
        log.notice("HTTP server started")
    except Exception as e:
        log.error(f"An error occurred: {e}")

def init():
    try:
        t_http = threading.Thread(target=http_server)
        t_http.start()

        restore_command = CFCliCommand(
            "dna_restore",
            restore_dna_data_from_file,
            "Restore DNA data"
        )
        restore_command.register()

        log.notice(f"{Config.PLUGIN_NAME} started!")
        return 0

    except Exception as e:
        log.error(f"An error occurred during plugin startup: {e}")

def deinit():
    return 0