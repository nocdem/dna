/* Suite selection flag: -DNODUS_TEST_ADMISSION=1; ordinary target uses
 * the other branch. This only selects test fixtures, not protocol constants. */
#if defined(NODUS_TEST_ADMISSION)
/* Approved build plan 4.3: role matrix, database faults, strict local wire,
 * both session roles, epoch boundaries and whole-list installation.
 * A failed boundary answer retains the last list; each new status asks
 * again until the current epoch's list is installed (operator dispatch).
 * Flags: NODUS_TEST_ADMISSION=1 (also compile with ASan/UBSan). Environment: none. Leaves
 * nothing: in-memory database, ephemeral sockets, identities released.
 * Positive controls require authenticated/open sessions and delivered data;
 * withholding an answer must never satisfy those assertions. Fake monotonic
 * time drives the exact deadline, independently of socket scheduling. */
#include "server/nodus_inter_session.h"
#include "server/nodus_inter_dial.h"
#include "server/nodus_chain_backend.h"
#include "server/nodus_server.h"
#include "witness/nodus_witness_ipc.h"
#include "witness/nodus_witness.h"
#include "dht/nodus_dht_ipc.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include "protocol/nodus_cbor.h"
#include <sqlite3.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", \
    __FILE__, __LINE__, #x); exit(1); } } while (0)
static nodus_identity_t ids[2];
static const uint8_t chain[32] = { 0x93 };
static bool duplicate_ip;
typedef struct {
    nodus_tcp_t tcp;
    nodus_inter_session_module_t *module;
    nodus_tcp_conn_t *conn;
    uint64_t now, height;
    bool known;
    nodus_inter_role_list_t held;
    bool have;
    unsigned frames, queries;
} end_t;
static uint64_t clock_ms(void *p) { return ((end_t *)p)->now; }
static bool status(void *p, uint8_t ci[32], uint64_t *h) {
    end_t *e = p; memcpy(ci, chain, 32); *h = e->height; return e->known;
}
static int role(void *p, const nodus_key_t *fp, bool *va, bool *st) {
    end_t *e = p; CHECK(fp != NULL); e->queries++;
    *va = *st = false;
    if (!e->have) return -1;
    nodus_inter_roles_lookup(&e->held, fp, va, st);
    return 1;
}
static void accept_conn(nodus_tcp_conn_t *c, void *p) { ((end_t *)p)->conn = c; }
static void closed(nodus_tcp_conn_t *c, void *p) {
    end_t *e = p; if (e->conn == c) e->conn = NULL;
}
static void received(nodus_tcp_conn_t *c, const uint8_t *p, size_t n, void *v) {
    end_t *e = v; CHECK(nodus_inter_session_is_open(c));
    CHECK(n == 1 && p[0] == 0x57); e->frames++;
}
static void init_end(end_t *e, unsigned id) {
    memset(e, 0, sizeof(*e)); e->now = 100; e->known = true; e->height = 1;
    CHECK(nodus_tcp_init(&e->tcp, -1) == 0);
    e->tcp.on_accept = accept_conn; e->tcp.on_disconnect = closed;
    e->tcp.on_frame = received; e->tcp.cb_ctx = e;
    nodus_inter_session_config_t cfg = {
        .identity = &ids[id], .inbound_depth = 64, .outbound_depth = 64,
        .status = status, .role = role, .admission_ctx = e,
        .now_ms = clock_ms, .now_ctx = e, .inbound_cap = 40,
        .allow_duplicate_ip = duplicate_ip
    };
    e->module = nodus_inter_session_new(&e->tcp, &cfg); CHECK(e->module);
}
static void step(end_t *a, end_t *b) {
    CHECK(nodus_tcp_poll(&a->tcp, 0) >= 0); CHECK(nodus_tcp_poll(&b->tcp, 0) >= 0);
    end_t *es[] = {a,b};
    for (unsigned i = 0; i < 2; ++i) {
        nodus_inter_session_job_t *j;
        while ((j = nodus_inter_session_job_take(es[i]->module))) {
            nodus_inter_session_job_run(j);
            (void)nodus_inter_session_job_done(es[i]->module, j);
        }
    }
}
static void install(end_t *e, unsigned peer, bool va, bool st) {
    memset(&e->held, 0, sizeof(e->held));
    e->held.height = e->height;
    if (va) e->held.validators[e->held.validator_count++] = ids[peer].node_id;
    if (st) e->held.storage[e->held.storage_count++] = ids[peer].node_id;
    e->have = true;
}
static void pair(end_t *a, end_t *b, bool have, bool va, bool st, unsigned side) {
    init_end(a, 0); init_end(b, 1);
    install(a, 1, true, false); install(b, 0, true, false);
    end_t *selected = side ? b : a;
    install(selected, side ? 0 : 1, va, st); selected->have = have;
    CHECK(nodus_tcp_listen(&b->tcp, "127.0.0.1", 0) == 0);
    a->conn = nodus_tcp_connect_pinned(&a->tcp, "127.0.0.1", b->tcp.port, &ids[1].node_id);
    CHECK(a->conn);
    uint8_t p = 0x57; CHECK(nodus_tcp_send(a->conn, &p, 1) == 0);
    for (unsigned i = 0; i < 10000 && !selected->queries; ++i) step(a,b);
    CHECK(selected->queries);
}
static void destroy(end_t *e) {
    nodus_tcp_close(&e->tcp); nodus_inter_session_free(e->module);
}
static void sessions(void) {
    /* The lookup below pins status-to-role mapping; here each endpoint's
     * test backend supplies that answer, independently on both directions. */
    const bool admitted[] = {true,true,true,true,true,false,false,false,false,false};
    for (unsigned side = 0; side < 2; ++side) {
        for (unsigned k = 0; k < sizeof(admitted)/sizeof(admitted[0]); ++k) {
            end_t a,b;
            pair(&a,&b,k != 9,admitted[k] && k < 3,admitted[k] && k >= 3,side);
            end_t *e = side ? &b : &a;
            for (unsigned i = 0; i < 1000; ++i) step(&a,&b);
            if (admitted[k]) {
                CHECK(e->conn && nodus_inter_session_is_open(e->conn));
                CHECK(b.frames == 1);
                /* Height changes alone do not invalidate the held list. */
                e->height = DNAC_EPOCH_LENGTH - 1; step(&a,&b);
                CHECK(e->conn && nodus_inter_session_is_open(e->conn));
                e->height = DNAC_EPOCH_LENGTH + 2;
                install(e,side ? 0 : 1,false,false);
                step(&a,&b); CHECK(!e->conn);
            } else {
                CHECK(!e->conn); CHECK(b.frames == 0);
                if (k==9) {
                    install(e,side ? 0 : 1,true,false);
                    step(&a,&b); CHECK(!e->conn); /* install cannot reopen a closed session */
                    a.conn=nodus_tcp_connect_pinned(&a.tcp,"127.0.0.1",b.tcp.port,&ids[1].node_id);
                    CHECK(a.conn);
                    uint8_t p=0x57; CHECK(!nodus_tcp_send(a.conn,&p,1));
                    for (unsigned i=0;i<10000 && !b.frames;++i) step(&a,&b);
                    CHECK(a.conn && b.conn && b.frames==1);
                    CHECK(nodus_inter_session_is_open(a.conn) && nodus_inter_session_is_open(b.conn));
                }
            }
            destroy(&a); destroy(&b);
        }
    }
    end_t a,b; init_end(&a,0); init_end(&b,1); a.known = false;
    CHECK(nodus_tcp_listen(&b.tcp,"127.0.0.1",0) == 0);
    CHECK(!nodus_inter_pool_dial(&a.tcp,"127.0.0.1",b.tcp.port,&ids[1].node_id));
    destroy(&a); destroy(&b);
}
static void held_list(void) {
    for (unsigned side = 0; side < 2; ++side) {
        for (unsigned storage_role = 0; storage_role < 2; ++storage_role) {
            end_t a,b; pair(&a,&b,true,!storage_role,storage_role,side);
            end_t *e = side ? &b : &a;
            for (unsigned i = 0; i < 10000 && !b.frames; ++i) step(&a,&b);
            CHECK(a.conn && b.conn && b.frames == 1);
            CHECK(nodus_inter_session_is_open(a.conn) && nodus_inter_session_is_open(b.conn));

            e->height = DNAC_EPOCH_LENGTH + 3;
            const uint64_t times[] = {3100, 10100, 1000100};
            for (unsigned t = 0; t < sizeof(times)/sizeof(times[0]); ++t) {
                e->now = times[t]; step(&a,&b);
                CHECK(e->conn && nodus_inter_session_is_open(e->conn));
                CHECK(nodus_inter_session_poll_timeout(e->module, 10000) == 10000);
                unsigned af = a.frames, bf = b.frames;
                uint8_t p = 0x57;
                CHECK(nodus_tcp_send(a.conn, &p, 1) == 0);
                CHECK(nodus_tcp_send(b.conn, &p, 1) == 0);
                for (unsigned i = 0; i < 10000 && (a.frames == af || b.frames == bf); ++i)
                    step(&a,&b);
                CHECK(a.frames == af+1 && b.frames == bf+1);
            }

            install(e,side ? 0 : 1,storage_role,!storage_role);
            step(&a,&b); CHECK(e->conn && nodus_inter_session_is_open(e->conn));
            install(e,side ? 0 : 1,false,false);
            step(&a,&b); CHECK(!e->conn);
            destroy(&a); destroy(&b);
        }
    }
}
/* Actual accepts, with source loopback addresses so the plain transport's
 * separate twenty-per-IP limit does not replace the forty-handshake test. */
static int silent_peer(uint16_t port, unsigned ip) {
    int fd=socket(AF_INET,SOCK_STREAM,0); CHECK(fd>=0);
    struct sockaddr_in local={.sin_family=AF_INET};
    local.sin_addr.s_addr=htonl(0x7f000000u|ip);
    CHECK(bind(fd,(struct sockaddr *)&local,sizeof(local))==0);
    struct sockaddr_in remote={.sin_family=AF_INET,.sin_port=htons(port)};
    remote.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    CHECK(connect(fd,(struct sockaddr *)&remote,sizeof(remote))==0);
    return fd;
}
static void accept_pass(end_t *b) {
    for (unsigned i=0;i<20;++i) CHECK(nodus_tcp_poll(&b->tcp,1)>=0);
}
static void k2(void) {
    end_t a,b; init_end(&a,0); init_end(&b,1);
    CHECK(nodus_tcp_listen(&b.tcp,"127.0.0.1",0)==0);
    int fd=silent_peer(b.tcp.port,1); accept_pass(&b);
    CHECK(b.tcp.count==1);
    int third=silent_peer(b.tcp.port,1); accept_pass(&b); CHECK(b.tcp.count==1);
    close(third); close(fd); destroy(&a); destroy(&b);
    pair(&a,&b,true,true,false,0);
    for(unsigned i=0;i<10000 && !b.frames;++i) step(&a,&b);
    CHECK(b.frames==1 && b.conn && nodus_inter_session_is_open(b.conn));
    fd=silent_peer(b.tcp.port,1); accept_pass(&b); CHECK(b.tcp.count==2);
    third=silent_peer(b.tcp.port,1); accept_pass(&b); CHECK(b.tcp.count==2);
    close(third); close(fd); destroy(&a); destroy(&b);

    duplicate_ip=true; init_end(&b,1); duplicate_ip=false;
    CHECK(nodus_tcp_listen(&b.tcp,"127.0.0.1",0)==0);
    fd=silent_peer(b.tcp.port,1); third=silent_peer(b.tcp.port,1);
    accept_pass(&b); CHECK(b.tcp.count==2);
    close(fd); close(third); destroy(&b);

    pair(&a,&b,true,true,false,0);
    for(unsigned i=0;i<10000 && !b.frames;++i) step(&a,&b);
    CHECK(b.frames==1);
    int fds[41];
    for(unsigned i=0;i<40;++i) {
        fds[i]=silent_peer(b.tcp.port,i+2); accept_pass(&b);
        CHECK(b.tcp.count==(int)i+2); /* admitted first session is exempt */
    }
    fds[40]=silent_peer(b.tcp.port,42); accept_pass(&b); CHECK(b.tcp.count==41);
    for(unsigned i=0;i<41;++i) close(fds[i]);
    destroy(&a); destroy(&b);
}
static void fail_second_row(sqlite3_context *ctx,int argc,sqlite3_value **argv) {
    CHECK(argc==1);
    int *calls=sqlite3_user_data(ctx);
    if (++*calls==2) sqlite3_result_error(ctx,"injected role scan failure",-1);
    else sqlite3_result_value(ctx,argv[0]);
}
static void lookup(void) {
    nodus_witness_t *w = calloc(1,sizeof(*w)); CHECK(w);
    CHECK(sqlite3_open(":memory:",&w->db) == SQLITE_OK);
    CHECK(sqlite3_exec(w->db,"CREATE TABLE validators(pubkey BLOB,status INTEGER);"
        "CREATE TABLE v2_storage_nodes(node_fp BLOB,status INTEGER);"
        "CREATE TABLE blocks(height INTEGER); INSERT INTO blocks VALUES(37);",NULL,NULL,NULL) == SQLITE_OK);
    sqlite3_stmt *s; nodus_inter_role_list_t list; bool va,st;
    for (int k = 0; k <= 4; ++k) {
        CHECK(sqlite3_prepare_v2(w->db,"INSERT INTO validators VALUES(?,?)",-1,&s,NULL)==SQLITE_OK);
        sqlite3_bind_blob(s,1,ids[0].pk.bytes,NODUS_PK_BYTES,SQLITE_STATIC); sqlite3_bind_int(s,2,k);
        CHECK(sqlite3_step(s)==SQLITE_DONE); sqlite3_finalize(s);
        CHECK(nodus_witness_roles_build(w,&list)==1 && list.height==37);
        va=st=false; nodus_inter_roles_lookup(&list,&ids[0].node_id,&va,&st);
        CHECK(va == (k==0 || k==1 || k==4) && !st);
        CHECK(sqlite3_exec(w->db,"DELETE FROM validators",NULL,NULL,NULL)==SQLITE_OK);
    }
    for (int k=1; k<=3; ++k) {
        CHECK(sqlite3_prepare_v2(w->db,"INSERT INTO v2_storage_nodes VALUES(?,?)",-1,&s,NULL)==SQLITE_OK);
        sqlite3_bind_blob(s,1,ids[0].node_id.bytes,64,SQLITE_STATIC); sqlite3_bind_int(s,2,k);
        CHECK(sqlite3_step(s)==SQLITE_DONE); sqlite3_finalize(s);
        CHECK(nodus_witness_roles_build(w,&list)==1);
        va=st=false; nodus_inter_roles_lookup(&list,&ids[0].node_id,&va,&st);
        CHECK(!va && st==(k==1 || k==2));
        CHECK(sqlite3_exec(w->db,"DELETE FROM v2_storage_nodes",NULL,NULL,NULL)==SQLITE_OK);
    }
    CHECK(nodus_witness_roles_build(w,&list)==1 && !list.validator_count && !list.storage_count);
    /* Full bounds, deliberately reverse-ordered rows. Validator hashes
     * must derive from pubkey; storage fingerprints are copied as stored. */
    for (unsigned i=0;i<DNAC_MAX_VALIDATORS;++i) {
        nodus_pubkey_t pk=ids[0].pk; pk.bytes[0]=(uint8_t)i;
        CHECK(sqlite3_prepare_v2(w->db,"INSERT INTO validators VALUES(?,0)",-1,&s,NULL)==SQLITE_OK);
        CHECK(sqlite3_bind_blob(s,1,pk.bytes,NODUS_PK_BYTES,SQLITE_TRANSIENT)==SQLITE_OK);
        CHECK(sqlite3_step(s)==SQLITE_DONE); CHECK(sqlite3_finalize(s)==SQLITE_OK);
    }
    /* HF-9 WP4 (plan §8.7): the live storage rows reach the generation-6
     * capacity 1024 - two distinguishing bytes, reverse-ordered */
    for (unsigned i=0;i<DNA_V2_STORAGE_SET_CAP;++i) {
        nodus_key_t fp={{0}};
        fp.bytes[0]=(uint8_t)((DNA_V2_STORAGE_SET_CAP-1-i)>>8);
        fp.bytes[1]=(uint8_t)((DNA_V2_STORAGE_SET_CAP-1-i)&255u);
        CHECK(sqlite3_prepare_v2(w->db,"INSERT INTO v2_storage_nodes VALUES(?,1)",-1,&s,NULL)==SQLITE_OK);
        CHECK(sqlite3_bind_blob(s,1,fp.bytes,NODUS_KEY_BYTES,SQLITE_TRANSIENT)==SQLITE_OK);
        CHECK(sqlite3_step(s)==SQLITE_DONE); CHECK(sqlite3_finalize(s)==SQLITE_OK);
    }
    CHECK(nodus_witness_roles_build(w,&list)==1);
    CHECK(list.validator_count==DNAC_MAX_VALIDATORS && list.storage_count==DNA_V2_STORAGE_SET_CAP);
    for (size_t i=1;i<list.validator_count;++i)
        CHECK(nodus_key_cmp(&list.validators[i-1],&list.validators[i])<0);
    for (size_t i=0;i<list.storage_count;++i)
        CHECK(list.storage[i].bytes[0]==(uint8_t)(i>>8) && list.storage[i].bytes[1]==(uint8_t)(i&255u));
    uint8_t buf[NODUS_WITNESS_IPC_ROLES_FRAME_MAX];
    list.height=UINT64_MAX; /* exercise the largest encoded height too */
    size_t n=nodus_inter_roles_encode(NODUS_WITNESS_IPC_Q_ROLES,&list,true,buf,sizeof(buf));
    nodus_inter_role_list_t decoded; bool ok=false;
    CHECK(n==sizeof(buf));
    CHECK(!nodus_inter_roles_decode(NODUS_WITNESS_IPC_Q_ROLES,buf,n,&decoded,&ok) && ok);
    CHECK(!memcmp(&list,&decoded,sizeof(list)));
    for (unsigned i=0;i<DNAC_MAX_VALIDATORS;++i) {
        nodus_pubkey_t pk=ids[0].pk; pk.bytes[0]=(uint8_t)i;
        nodus_key_t fp; CHECK(!nodus_fingerprint(&pk,&fp));
        nodus_inter_roles_lookup(&list,&fp,&va,&st); CHECK(va);
    }
    n=nodus_dht_ipc_encode_roles(&list,true,buf,sizeof(buf));
    nodus_dht_ipc_msg_t msg;
    CHECK(n==sizeof(buf)-1 && !nodus_dht_ipc_decode(buf,n,&msg,NULL,0));
    CHECK(msg.ok && !memcmp(&msg.roles,&list,sizeof(list)));
    CHECK(sqlite3_exec(w->db,"INSERT INTO validators SELECT * FROM validators LIMIT 1",NULL,NULL,NULL)==SQLITE_OK);
    CHECK(nodus_witness_roles_build(w,&list)==-1 && !list.validator_count && !list.storage_count);
    CHECK(sqlite3_exec(w->db,"DELETE FROM validators; INSERT INTO v2_storage_nodes SELECT * FROM v2_storage_nodes LIMIT 1",NULL,NULL,NULL)==SQLITE_OK);
    CHECK(nodus_witness_roles_build(w,&list)==-1 && !list.validator_count && !list.storage_count);
    CHECK(sqlite3_exec(w->db,"DROP TABLE validators; DELETE FROM v2_storage_nodes;"
        "CREATE TABLE fault_rows(pk BLOB)",NULL,NULL,NULL)==SQLITE_OK);
    CHECK(sqlite3_prepare_v2(w->db,"INSERT INTO fault_rows VALUES(?),(?)",-1,&s,NULL)==SQLITE_OK);
    CHECK(sqlite3_bind_blob(s,1,ids[0].pk.bytes,NODUS_PK_BYTES,SQLITE_STATIC)==SQLITE_OK);
    CHECK(sqlite3_bind_blob(s,2,ids[1].pk.bytes,NODUS_PK_BYTES,SQLITE_STATIC)==SQLITE_OK);
    CHECK(sqlite3_step(s)==SQLITE_DONE && sqlite3_finalize(s)==SQLITE_OK);
    int calls=0;
    CHECK(sqlite3_create_function(w->db,"role_read",1,SQLITE_UTF8,&calls,fail_second_row,NULL,NULL)==SQLITE_OK);
    CHECK(sqlite3_exec(w->db,"CREATE VIEW validators AS SELECT role_read(pk) AS pubkey,0 AS status FROM fault_rows",NULL,NULL,NULL)==SQLITE_OK);
    CHECK(nodus_witness_roles_build(w,&list)==-1 && calls==2 && !list.validator_count && !list.storage_count);
    CHECK(sqlite3_exec(w->db,"DROP VIEW validators",NULL,NULL,NULL)==SQLITE_OK);
    CHECK(nodus_witness_roles_build(w,&list)==-1 && !list.validator_count && !list.storage_count);
    n=nodus_inter_roles_encode(NODUS_WITNESS_IPC_Q_ROLES,&list,false,buf,sizeof(buf));
    CHECK(n && !nodus_inter_roles_decode(NODUS_WITNESS_IPC_Q_ROLES,buf,n,&decoded,&ok));
    CHECK(!ok && !decoded.validator_count && !decoded.storage_count);
    sqlite3_close(w->db); free(w);
}
static void strict_variants(bool is_role, bool answer) {
    /* For each required key, test omission and wrong type; also an extra
     * known key, an unknown key and a duplicate q. */
    const char *role_keys[]={"q","h","ok","va","st"};
    const char *status_keys[]={"q","co","h","ci","ch"};
    const char **keys=is_role ? role_keys : status_keys;
    unsigned count=answer ? 5 : 1;
    for(unsigned wire=0;wire<(is_role && answer ? 2u : 1u);++wire)
    for(unsigned variant=0;variant<3;++variant) {
        unsigned tries=variant<2 ? count : 3;
        for(unsigned bad=0;bad<tries;++bad) {
            uint8_t buf[512]; cbor_encoder_t e; cbor_encoder_init(&e,buf,sizeof(buf));
            cbor_encode_map(&e,count+(variant==2 ? 1 : 0)-(variant==0 ? 1 : 0));
            for(unsigned i=0;i<count;++i) {
                if(variant==0 && i==bad) continue;
                const char *k=keys[i]; cbor_encode_cstr(&e,k);
                if(variant==1 && i==bad) {
                    if(!strcmp(k,"ok") || !strcmp(k,"va") || !strcmp(k,"st") ||
                       !strcmp(k,"co") || !strcmp(k,"ch")) cbor_encode_uint(&e,2);
                    else cbor_encode_array(&e,0);
                    continue;
                }
                if(i==0) cbor_encode_cstr(&e,is_role ?
                    (wire ? NODUS_WITNESS_IPC_Q_ROLES : NODUS_DHT_IPC_Q_ROLES) : NODUS_DHT_IPC_Q_STATUS);
                else if(!strcmp(k,"va") || !strcmp(k,"st")) cbor_encode_array(&e,0);
                else if(!strcmp(k,"ci")) cbor_encode_bstr(&e,chain,32);
                else if(!strcmp(k,"h")) cbor_encode_uint(&e,7);
                else cbor_encode_bool(&e,true);
            }
            if(variant==2) {
                cbor_encode_cstr(&e,bad==0 ? "v" : bad==1 ? "unknown" : "q");
                cbor_encode_uint(&e,1);
            }
            nodus_dht_ipc_msg_t msg;
            CHECK(!e.error);
            if (wire) {
                nodus_inter_role_list_t list; bool ok;
                CHECK(nodus_inter_roles_decode(NODUS_WITNESS_IPC_Q_ROLES,buf,cbor_encoder_len(&e),&list,&ok)==-1);
            } else CHECK(nodus_dht_ipc_decode(buf,cbor_encoder_len(&e),&msg,NULL,0)==-1);
        }
    }
}
static void wire(void) {
    uint8_t buf[512]; nodus_dht_ipc_msg_t m;
    size_t n = nodus_dht_ipc_encode_status(NULL,buf,sizeof(buf)); CHECK(n);
    CHECK(!nodus_dht_ipc_decode(buf,n,&m,NULL,0) && !m.answer);
    nodus_dht_ipc_msg_t st = {.chain_open=true,.height=8,.chain_here=true}; memcpy(st.chain_id,chain,32);
    n = nodus_dht_ipc_encode_status(&st,buf,sizeof(buf)); CHECK(n);
    CHECK(!nodus_dht_ipc_decode(buf,n,&m,NULL,0) && m.answer && m.chain_here && m.height==8);
    buf[0]++; CHECK(nodus_dht_ipc_decode(buf,n,&m,NULL,0)==-1); /* missing key */
    n = nodus_dht_ipc_encode_roles(NULL,true,buf,sizeof(buf)); CHECK(n);
    CHECK(!nodus_dht_ipc_decode(buf,n,&m,NULL,0) && !m.answer);
    nodus_inter_role_list_t r = {.height=8,.validator_count=1,.storage_count=1};
    r.validators[0]=r.storage[0]=ids[0].node_id;
    n = nodus_dht_ipc_encode_roles(&r,true,buf,sizeof(buf)); CHECK(n);
    CHECK(!nodus_dht_ipc_decode(buf,n,&m,NULL,0) && m.answer && m.ok &&
          m.roles.validator_count==1 && m.roles.storage_count==1 && m.roles.height==8);
    CHECK(nodus_dht_ipc_decode(buf,n-1,&m,NULL,0)==-1);
    n = nodus_dht_ipc_encode_status(&st,buf,sizeof(buf)); CHECK(n);
    CHECK(buf[n-1]==0xf5); buf[n-1]=0x01; /* ch must be bool */
    CHECK(nodus_dht_ipc_decode(buf,n,&m,NULL,0)==-1);
}

static void array_refusals(void) {
    const char *names[]={NODUS_DHT_IPC_Q_ROLES,NODUS_WITNESS_IPC_Q_ROLES};
    for (unsigned wire=0;wire<2;++wire) for (unsigned field=0;field<2;++field)
    for (unsigned fault=0;fault<3;++fault) {
        uint8_t buf[NODUS_WITNESS_IPC_ROLES_FRAME_MAX+128];
        cbor_encoder_t e; cbor_encoder_init(&e,buf,sizeof(buf));
        cbor_encode_map(&e,5);
        cbor_encode_cstr(&e,"q"); cbor_encode_cstr(&e,names[wire]);
        cbor_encode_cstr(&e,"ok"); cbor_encode_bool(&e,true);
        cbor_encode_cstr(&e,"h"); cbor_encode_uint(&e,1);
        for (unsigned a=0;a<2;++a) {
            cbor_encode_cstr(&e,a ? "st" : "va");
            size_t count=a!=field ? 0 : fault==2 ?
                (a ? DNA_V2_STORAGE_SET_CAP : DNAC_MAX_VALIDATORS)+1 : 1;
            cbor_encode_array(&e,count);
            for (size_t i=0;i<count;++i) {
                if (fault==0) cbor_encode_uint(&e,7);
                else cbor_encode_bstr(&e,ids[0].node_id.bytes,fault==1 ? 63 : 64);
            }
        }
        CHECK(!e.error);
        nodus_dht_ipc_msg_t msg; nodus_inter_role_list_t list; bool ok;
        if (wire==0) CHECK(nodus_dht_ipc_decode(buf,cbor_encoder_len(&e),&msg,NULL,0)==-1);
        else CHECK(nodus_inter_roles_decode(names[wire],buf,cbor_encoder_len(&e),&list,&ok)==-1);
    }
}

/* Real IPC backend, controlled status answers: no timer sleeps and no
 * boundary modulo assumption. The raw witness intentionally drops requests
 * or returns faults, so query counts cannot pass without the actual wiring. */
typedef struct {
    nodus_tcp_t tcp;
    nodus_tcp_conn_t *ctl;
    unsigned queries;
    bool reply, ok;
    nodus_inter_role_list_t list;
} boundary_t;
static void boundary_frame(nodus_tcp_conn_t *c,const uint8_t *p,size_t n,void *ctx) {
    boundary_t *w=ctx; w->ctl=c;
    cbor_decoder_t d; cbor_decoder_init(&d,p,n);
    cbor_item_t m=cbor_decode_next(&d), k=cbor_decode_next(&d), v=cbor_decode_next(&d);
    CHECK(m.type==CBOR_ITEM_MAP && m.count==1 && k.type==CBOR_ITEM_TSTR &&
          k.tstr.len==1 && k.tstr.ptr[0]=='q' && v.type==CBOR_ITEM_TSTR && !d.error && d.pos==n);
    if (v.tstr.len!=strlen(NODUS_WITNESS_IPC_Q_ROLES) ||
        memcmp(v.tstr.ptr,NODUS_WITNESS_IPC_Q_ROLES,v.tstr.len)) return;
    w->queries++;
    if (w->reply) {
        uint8_t buf[NODUS_WITNESS_IPC_ROLES_FRAME_MAX];
        n=nodus_inter_roles_encode(NODUS_WITNESS_IPC_Q_ROLES,&w->list,w->ok,buf,sizeof(buf));
        CHECK(n && nodus_tcp_send(c,buf,n)==0);
    }
}
static void boundary_pump(boundary_t *w,nodus_chain_backend_t *b) {
    for (unsigned i=0;i<20;++i) {
        b->ops->tick(b); CHECK(nodus_tcp_poll(&w->tcp,0)>=0);
    }
}
static void boundary_status(boundary_t *w,nodus_chain_backend_t *b,uint64_t h,bool co) {
    uint8_t buf[512]; cbor_encoder_t e; cbor_encoder_init(&e,buf,sizeof(buf));
    cbor_encode_map(&e,7);
    cbor_encode_cstr(&e,"q"); cbor_encode_cstr(&e,NODUS_WITNESS_IPC_Q_STATUS);
    cbor_encode_cstr(&e,"co"); cbor_encode_bool(&e,co);
    cbor_encode_cstr(&e,"h"); cbor_encode_uint(&e,h);
    cbor_encode_cstr(&e,"sr"); uint8_t root[64]={0}; cbor_encode_bstr(&e,root,64);
    cbor_encode_cstr(&e,"ci"); cbor_encode_bstr(&e,chain,32);
    cbor_encode_cstr(&e,"po"); cbor_encode_bool(&e,false);
    cbor_encode_cstr(&e,"lp"); cbor_encode_uint(&e,0);
    CHECK(!e.error && nodus_tcp_send(w->ctl,buf,cbor_encoder_len(&e))==0);
    boundary_pump(w,b);
}
static void boundary(void) {
    char dir[]="/tmp/nodus_role_epoch_XXXXXX",path[160]; CHECK(mkdtemp(dir));
    boundary_t w={0}; CHECK(nodus_tcp_init(&w.tcp,-1)==0);
    w.tcp.on_frame=boundary_frame; w.tcp.cb_ctx=&w;
    CHECK(!nodus_witness_ipc_sock_path(dir,path,sizeof(path)));
    CHECK(!nodus_tcp_unix_listen(&w.tcp,path,NODUS_TCP_UNIX_UID_SELF));
    nodus_chain_backend_t *b=NULL; CHECK(!nodus_chain_backend_ipc_open(dir,&b));
    boundary_pump(&w,b); CHECK(w.ctl);
    nodus_inter_role_list_t held;
    CHECK(b->ops->roles(b,&held)==0);
    boundary_status(&w,b,1,false); CHECK(w.queries==0);
    boundary_status(&w,b,1,true); CHECK(w.queries==1);
    boundary_status(&w,b,2,true); CHECK(w.queries==2); /* dropped first query */
    w.reply=true; w.ok=false;
    boundary_status(&w,b,3,true); CHECK(w.queries==3 && b->ops->roles(b,&held)==0);
    w.ok=true; w.list.height=4; w.list.validator_count=1; w.list.validators[0]=ids[0].node_id;
    boundary_status(&w,b,4,true); CHECK(w.queries==4 && b->ops->roles(b,&held)==1);
    boundary_status(&w,b,DNAC_EPOCH_LENGTH-1,true); CHECK(w.queries==4);
    w.ok=false;
    boundary_status(&w,b,DNAC_EPOCH_LENGTH+3,true); CHECK(w.queries==5);
    CHECK(b->ops->roles(b,&held)==1 && held.height==4 && held.validator_count==1);
    w.ok=true; w.list.height=DNAC_EPOCH_LENGTH+4; w.list.validator_count=0;
    boundary_status(&w,b,DNAC_EPOCH_LENGTH+4,true); CHECK(w.queries==6);
    CHECK(b->ops->roles(b,&held)==1 && held.height==w.list.height && !held.validator_count);
    boundary_status(&w,b,DNAC_EPOCH_LENGTH+5,true); CHECK(w.queries==6);
    w.list.height=3*DNAC_EPOCH_LENGTH+7;
    boundary_status(&w,b,w.list.height,true); CHECK(w.queries==7);
    boundary_status(&w,b,w.list.height+1,true); CHECK(w.queries==7);
    b->ops->close(b); nodus_tcp_close(&w.tcp); CHECK(!rmdir(dir));
}

typedef struct {
    nodus_chain_backend_t base;
    nodus_inter_role_list_t list;
    uint64_t height;
    unsigned queries;
    int answer;
    bool open;
} combined_t;
static bool combined_open(nodus_chain_backend_t *b) { return ((combined_t *)b)->open; }
static void combined_status(nodus_chain_backend_t *b,nodus_t2_status_info_t *st) {
    st->block_height=((combined_t *)b)->height; memcpy(st->chain_id,chain,32);
}
static int combined_roles(nodus_chain_backend_t *b,nodus_inter_role_list_t *list) {
    combined_t *f=(combined_t *)b; f->queries++; *list=f->list; return f->answer;
}
static void combined_boundary(void) {
    static const nodus_chain_backend_ops_t ops={
        .chain_open=combined_open,.status=combined_status,.roles=combined_roles
    };
    combined_t f={.base={.ops=&ops},.height=1,.answer=-1};
    nodus_server_t *srv=calloc(1,sizeof(*srv)); CHECK(srv); srv->chain=&f.base;
    nodus_server_inter_chain_refresh(srv); CHECK(!f.queries && !srv->inter_roles_have);
    f.open=true;
    nodus_server_inter_chain_refresh(srv); CHECK(f.queries==1 && !srv->inter_roles_have);
    nodus_server_inter_chain_refresh(srv); CHECK(f.queries==2 && !srv->inter_roles_have);
    f.answer=1; f.list.height=1; f.list.validator_count=1; f.list.validators[0]=ids[0].node_id;
    nodus_server_inter_chain_refresh(srv); CHECK(f.queries==3 && srv->inter_roles_have);
    f.height=DNAC_EPOCH_LENGTH-1;
    nodus_server_inter_chain_refresh(srv); CHECK(f.queries==3);
    f.height=DNAC_EPOCH_LENGTH+3; f.answer=-1;
    nodus_server_inter_chain_refresh(srv); CHECK(f.queries==4 && srv->inter_roles.validator_count==1);
    f.answer=1; f.list.height=f.height; f.list.validator_count=0;
    nodus_server_inter_chain_refresh(srv); CHECK(f.queries==5 && !srv->inter_roles.validator_count);
    f.height++;
    nodus_server_inter_chain_refresh(srv); CHECK(f.queries==5);
    f.height=3*DNAC_EPOCH_LENGTH+7; f.list.height=f.height;
    nodus_server_inter_chain_refresh(srv); CHECK(f.queries==6);
    free(srv);
}
int main(void) {
    CHECK(nodus_identity_generate(&ids[0])==0); CHECK(nodus_identity_generate(&ids[1])==0);
    lookup(); wire(); array_refusals(); boundary(); combined_boundary();
    strict_variants(false,false); strict_variants(false,true);
    strict_variants(true,false); strict_variants(true,true);
    sessions(); held_list(); k2();
    nodus_identity_clear(&ids[0]); nodus_identity_clear(&ids[1]); return 0;
}
#else
/* Build plan 4.3: The machine message order replaces method-name roles: duplicate KEYX and other-port/chain HELLO are refused.
 * Reuse the real-machine fixture and raw-peer checks of test_inter_session.
 * Flags: none; also ASan/UBSan. Environment: none. Leaves nothing.
 * Positive controls require delivered frames; no worker progress cannot pass.
 */
#define main inter_session_fixture_all_cases
#include "test_inter_session.c"
#undef main
int main(void) {
    (void)inter_session_fixture_all_cases;
    CHECK(nodus_identity_generate(&ids[0])==0 && nodus_identity_generate(&ids[1])==0);
    bad_keyx(false); mismatch(CMT_P2P_SC_PROTO_VER_4004,false); mismatch(8,false); mismatch(CMT_P2P_SC_PROTO_VER_4002,true);
    nodus_identity_clear(&ids[0]); nodus_identity_clear(&ids[1]);
    return 0;
}
#endif
