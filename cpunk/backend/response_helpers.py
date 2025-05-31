from pycfhelpers.node.http.simple import CFSimpleHTTPResponse
from pycfhelpers.node.logging import CFLog
import json

log = CFLog()

def send_json_response(message=None, desc=None, status_code=0, response_data=None):
    response_dict = {
        "status_code": status_code
    }

    if response_data:
        response_dict["response_data"] = response_data
    if message:
        response_dict["message"] = message
    if desc:
        response_dict["description"] = desc

    response_body = json.dumps(response_dict, indent=4).encode("utf-8")
    log.notice(response_body)
    return CFSimpleHTTPResponse(
        body=response_body,
        code=200,
        headers={"Content-Type": "application/json"}
    )
