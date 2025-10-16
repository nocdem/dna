/*
 * API Handler: GET /health
 */

#include "keyserver.h"
#include "http_utils.h"
#include "db.h"
#include <sys/sysinfo.h>

enum MHD_Result api_health_handler(struct MHD_Connection *connection, PGconn *db_conn) {
    json_object *response = json_object_new_object();

    // Basic health status
    json_object_object_add(response, "status", json_object_new_string("ok"));
    json_object_object_add(response, "version", json_object_new_string(KEYSERVER_VERSION));

    // Uptime
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        json_object_object_add(response, "uptime", json_object_new_int64(info.uptime));
    }

    // Database status
    if (db_conn && PQstatus(db_conn) == CONNECTION_OK) {
        json_object_object_add(response, "database", json_object_new_string("connected"));

        // Get total identities count
        int total = db_count_identities(db_conn);
        if (total >= 0) {
            json_object_object_add(response, "total_identities", json_object_new_int(total));
        }
    } else {
        json_object_object_add(response, "database", json_object_new_string("disconnected"));
    }

    return http_send_json_response(connection, HTTP_OK, response);
}
