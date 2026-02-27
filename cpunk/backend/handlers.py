from response_helpers import send_json_response
from pycfhelpers.node.logging import CFLog
from utils import Utils as u
from urllib.parse import parse_qs
import json, traceback
from gdb_ops import GlobalDBOps

log = CFLog()
gdb_ops = GlobalDBOps()

def request_handler(request):
    headers = request.headers
    body = request.body
    query = request.query
    client_ip = request.client_address

    log.notice(f"Received request from {client_ip} with {body} and headers {headers}")

    if body:
        try:
            payload = body.decode("utf-8")
        except UnicodeDecodeError:
            return send_json_response("NOK", "Invalid JSON data!", -1)

    if request.method == "POST":
        return handle_post_request(payload)

    if request.method == "GET":
        return handle_get_request(query)

    return send_json_response("NOK", "Invalid request method!", -1)

def handle_post_request(payload):
    try:
        validation_error = u.validate_json_data(payload)
        if validation_error:
            log.error(f"Data is invalid! {validation_error}")
            return send_json_response("NOK", validation_error, -1)

        if isinstance(payload, str):
            data = json.loads(payload)
        else:
            data = payload
        action = data.get("action")
        if not action:
            return send_json_response("NOK", "Action not provided", -1)
        log.notice(f"Processing action: {action}")
        if action == "add":
            return gdb_ops.write_gdb_data(data)
        elif action == "update":
            return gdb_ops.update_gdb_data_old_name(data)
        else:
            return send_json_response("NOK", "Invalid action", -1)
    except Exception as e:
        log.error(f"Error while processing action: {e}")
        log.error(traceback.format_exc())
        return send_json_response("NOK", f"Error while processing action", -1)

def handle_get_request(query):
    try:
        query_params_raw = parse_qs(query)
        query_params = {k: v[0] for k, v in query_params_raw.items()}
        log.notice(f"Processing GET request with query params: {query_params}")

        if "tx_validate" in query_params:
            tx_hash = query_params["tx_validate"]
            network = query_params.get("network", None)
            return u.is_tx_accepted(tx_hash, network)

        if "lookup" in query_params:
            return gdb_ops.gdb_lookup(query_params["lookup"])

        if "lookup2" in query_params:
            return gdb_ops.gdb_lookup(query_params["lookup2"], as_list=True)

        if "by_telegram" in query_params:
            return gdb_ops.gdb_lookup(query_params["by_telegram"], by_telegram_name=True)

        if "by_order" in query_params:
            return gdb_ops.gdb_lookup(query_params["by_order"], by_order_hash=True)

        if "all_delegations" in query_params:
            return gdb_ops.gdb_lookup("all_delegations")

        return send_json_response("NOK", "Missing or invalid query parameter!", -1)

    except Exception as e:
        log.error(traceback.format_exc())
        return send_json_response("NOK", f"Failed to process request!", -1)
