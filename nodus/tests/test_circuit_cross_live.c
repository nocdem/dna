/* Suite selection flag: -DNODUS_TEST_INTER_LAYOUT=1; ordinary target uses
 * the other branch. This only selects test fixtures, not protocol constants. */
#if defined(NODUS_TEST_INTER_LAYOUT)
/* Build plan 4.3: real core 4002, storage pool and batch forward in both
 * layouts. Fixed ports 24400..24402 and 24410..24412: run serially.
 * Flags: NODUS_TEST_INTER_LAYOUT=1; also ASan/UBSan. Environment: none. Temporary directories,
 * sockets, workers and identities are removed. Positive controls require
 * two independently admitted connections at the receiver and a completed
 * batch; merely starting a dial cannot pass. The witness below is a local
 * control-plane fixture, with real session crypto on the network path. */
#include "server/nodus_server.h"
#include "server/nodus_dht_backend.h"
#include "dht/nodus_dht_ipc.h"
#include "witness/nodus_witness_ipc.h"
#include "protocol/nodus_wire.h"
#include "crypto/nodus_identity.h"
#include "server/nodus_presence.h"
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x); exit(1); } } while(0)
static const uint8_t ci[32]={0x42};
typedef struct {
    nodus_chain_backend_t base;
    bool known, validator, storage;
    unsigned roles;
    int answer;
    uint64_t height;
} chain_t;
static nodus_server_t *receiver,*core;
static uint64_t storage_now;
static uint64_t storage_clock(void *ctx) { (void)ctx; return storage_now; }
static void tick(nodus_chain_backend_t *b) { (void)b; }
static bool pending(nodus_chain_backend_t *b) { (void)b; return false; }
static bool chain_open(nodus_chain_backend_t *b) { return ((chain_t *)b)->known; }
static void status(nodus_chain_backend_t *b,nodus_t2_status_info_t *st) {
    if (!chain_open(b)) return;
    memcpy(st->chain_id,ci,32); st->block_height=((chain_t *)b)->height;
}
static void peers(nodus_inter_role_list_t *out,bool va,bool st,uint64_t height) {
    memset(out,0,sizeof(*out)); out->height=height;
    nodus_key_t keys[]={receiver->identity.node_id,core->identity.node_id};
    if (nodus_key_cmp(&keys[0],&keys[1])>0) {
        nodus_key_t swap=keys[0]; keys[0]=keys[1]; keys[1]=swap;
    }
    if (va) { memcpy(out->validators,keys,sizeof(keys)); out->validator_count=2; }
    if (st) { memcpy(out->storage,keys,sizeof(keys)); out->storage_count=2; }
}
static int roles(nodus_chain_backend_t *b,nodus_inter_role_list_t *out) {
    chain_t *c=(chain_t *)b;
    if (!receiver || !core) return 0;
    c->roles++;
    peers(out,c->validator,c->storage,c->height); return c->answer;
}
static int port(nodus_chain_backend_t *b,bool *opened) { (void)b; *opened=false; return 0; }
static void session_closed(nodus_chain_backend_t *b,nodus_tcp_conn_t *c) { (void)b; (void)c; }
static void close_chain(nodus_chain_backend_t *b) { free(b); }
static const nodus_chain_backend_ops_t ops={
    .tick=tick,.read_pending=pending,.status=status,.chain_open=chain_open,
    .roles=roles,.listen_port=port,.session_closed=session_closed,.close=close_chain
};
static int new_chain(const nodus_witness_host_t *h,const nodus_witness_config_t *cfg,
                       nodus_chain_backend_t **out) {
    (void)h; (void)cfg; chain_t *c=calloc(1,sizeof(*c)); CHECK(c);
    c->known=true; c->validator=true; c->answer=1; c->height=1;
    c->base.ops=&ops; *out=&c->base; return 0;
}
typedef struct { unsigned statuses,roles; } witness_t;
static void wstatus(void *ctx,nodus_witness_ipc_status_t *st) {
    witness_t *w=ctx; w->statuses++; memset(st,0,sizeof(*st));
    st->chain_open=true; st->height=1; memcpy(st->chain_id,ci,32);
}
static int wroles(void *ctx,nodus_inter_role_list_t *out) {
    ((witness_t *)ctx)->roles++; peers(out,true,false,1); return 1;
}
static void wdispatch(void *ctx,nodus_tcp_conn_t *c,const uint8_t *p,size_t n,
                       const char *method,uint32_t txn) {
    (void)ctx; (void)c; (void)p; (void)n; (void)method; (void)txn; CHECK(false);
}
static void wcollect(void *ctx,nodus_tcp_conn_t *c,const uint8_t pk[NODUS_PK_BYTES],
                      const uint8_t token[NODUS_SESSION_TOKEN_LEN],
                      const uint8_t *p,size_t n,uint32_t txn) {
    (void)pk; (void)token; wdispatch(ctx,c,p,n,"",txn);
}
static nodus_dht_ipc_t *storage;
static nodus_dht_t *dht;
static nodus_witness_ipc_t *witness;
static int max_open;
static void pump(void) {
    core->chain->ops->tick(core->chain);
    nodus_server_inter_chain_refresh(core);
    nodus_server_inter_chain_refresh(receiver);
    core->dht->ops->tick(core->dht);
    nodus_dht_ipc_poll(storage,1); nodus_dht_ipc_tick(storage);
    nodus_witness_ipc_poll(witness,0);
    nodus_tcp_poll(&receiver->inter_tcp,0);
    int open=0;
    for(int i=0;i<NODUS_TCP_MAX_CONNS;++i)
        if(nodus_inter_session_is_open(receiver->inter_tcp.pool[i])) open++;
    if(open>max_open) max_open=open;
    nodus_dht_tick(dht);
}
static nodus_server_t *new_server(const char *dir,int base,bool split,bool external) {
    nodus_server_config_t cfg={0};
    snprintf(cfg.bind_ip,sizeof(cfg.bind_ip),"127.0.0.1");
    snprintf(cfg.data_path,sizeof(cfg.data_path),"%s",dir);
    cfg.udp_port=(uint16_t)base; cfg.tcp_port=(uint16_t)(base+1); cfg.peer_port=(uint16_t)(base+2);
    cfg.require_peer_auth=true; cfg.storage_external=split; cfg.witness_external=external;
    nodus_server_backends_t be=nodus_server_backends_inproc; be.chain_open=new_chain;
    nodus_server_t *srv=calloc(1,sizeof(*srv)); CHECK(srv);
    CHECK(nodus_server_init_ex(srv,&cfg,&be)==0); return srv;
}
static void old_hello(void) {
    int fd=socket(AF_INET,SOCK_STREAM,0); CHECK(fd>=0);
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(receiver->inter_tcp.port)};
    a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    CHECK(connect(fd,(struct sockaddr *)&a,sizeof(a))==0);
    uint8_t p[8192],fr[8200]; size_t n=0;
    CHECK(nodus_t2_hello(0,&core->identity.pk,&core->identity.node_id,p,sizeof(p),&n)==0);
    size_t fn=nodus_frame_encode(fr,sizeof(fr),p,(uint32_t)n); CHECK(fn);
    CHECK(send(fd,fr,fn,0)==(ssize_t)fn);
    for(unsigned i=0;i<30;++i) nodus_tcp_poll(&receiver->inter_tcp,1);
    uint8_t b; ssize_t got=recv(fd,&b,1,MSG_DONTWAIT);
    CHECK(got==0 || (got<0 && errno==ECONNRESET));
    CHECK(receiver->inter_tcp.count==0); close(fd);
}
static void origin_queries(nodus_dht_host_t *host, const char *sock) {
    /* Storage -> core: a control query on an existing origin closes it. */
    for(unsigned which=0;which<2;++which) {
        nodus_dht_origin_t o={NODUS_DHT_ORIGIN_CLIENT,12,which+1};
        core->dht->ops->session_opened(core->dht,o);
        uint8_t p[512],token[NODUS_SESSION_TOKEN_LEN]={0}; size_t n=0;
        nodus_key_t key={{0x66}};
        CHECK(nodus_t2_listen(20+which,token,&key,p,sizeof(p),&n)==0);
        nodus_tier2_msg_t m={0}; CHECK(nodus_t2_decode(p,n,&m)==0);
        core->dht->ops->client_frame(core->dht,12,&core->identity.node_id,
                                      &core->identity.pk,p,n,&m);
        nodus_t2_msg_free(&m);
        for(unsigned i=0;i<1000 && !dht->sessions[12].open;++i) pump();
        CHECK(dht->sessions[12].open);
        n=which ? nodus_dht_ipc_encode_status(NULL,p,sizeof(p)) :
                  nodus_dht_ipc_encode_roles(NULL,true,p,sizeof(p));
        CHECK(n && host->send_to_origin(host->ctx,o,p,n)==0);
        for(unsigned i=0;i<1000 && dht->sessions[12].open;++i) pump();
        CHECK(!dht->sessions[12].open);
    }
    /* Core -> storage: the same queries are refused on origin carriers.
     * This raw control replaces the fixture core at the end of the case. */
    nodus_tcp_t raw; CHECK(nodus_tcp_init(&raw,-1)==0);
    nodus_tcp_conn_t *ctl=nodus_tcp_unix_connect(&raw,sock,NODUS_TCP_UNIX_UID_SELF); CHECK(ctl);
    uint8_t boot[8]; memset(boot,0x88,sizeof(boot));
    uint8_t buf[NODUS_PK_BYTES+512];
    size_t n=nodus_dht_ipc_encode_ctl(boot,buf,sizeof(buf));
    CHECK(n && nodus_tcp_send(ctl,buf,n)==0);
    for(unsigned i=0;i<20;++i) {
        nodus_tcp_poll(&raw,0); nodus_dht_ipc_poll(storage,1); nodus_dht_ipc_tick(storage);
    }
    for(unsigned which=0;which<2;++which) {
        nodus_tcp_conn_t *c=nodus_tcp_unix_connect(&raw,sock,NODUS_TCP_UNIX_UID_SELF); CHECK(c);
        int slot=c->slot;
        nodus_dht_ipc_preface_t pf={0};
        pf.origin=(nodus_dht_origin_t){NODUS_DHT_ORIGIN_CLIENT,40+(int)which,1};
        memcpy(pf.boot,boot,8); pf.fp=core->identity.node_id; pf.pk=core->identity.pk;
        n=nodus_dht_ipc_encode_origin(&pf,buf,sizeof(buf));
        CHECK(n && nodus_tcp_send(c,buf,n)==0);
        n=which ? nodus_dht_ipc_encode_status(NULL,buf,sizeof(buf)) :
                  nodus_dht_ipc_encode_roles(NULL,true,buf,sizeof(buf));
        CHECK(n && nodus_tcp_send(c,buf,n)==0);
        for(unsigned i=0;i<1000 && raw.pool[slot];++i) {
            nodus_tcp_poll(&raw,0); nodus_dht_ipc_poll(storage,1); nodus_dht_ipc_tick(storage);
        }
        CHECK(!raw.pool[slot]);
    }
    nodus_tcp_close(&raw);
}

static void layout(bool external) {
    char remote_dir[]="/tmp/nodus_inter_remote_XXXXXX";
    char local_dir[]="/tmp/nodus_inter_local_XXXXXX";
    CHECK(mkdtemp(remote_dir) && mkdtemp(local_dir));
    max_open=0; witness=NULL; receiver=core=NULL;
    receiver=new_server(remote_dir,24400,false,false);
    core=new_server(local_dir,24410,true,external);
    old_hello();
    storage_now=100;
    storage=nodus_dht_ipc_new_clock(&core->identity,true,storage_clock,NULL); CHECK(storage);
    nodus_dht_host_t host; nodus_dht_ipc_host(storage,&host);
    dht=calloc(1,sizeof(*dht)); CHECK(dht && nodus_dht_init(dht,&host)==0);
    CHECK(nodus_dht_ipc_open_storage(dht,local_dir,"127.0.0.1",24412)==0);
    nodus_dht_ipc_attach(storage,dht);
    char sock[160]; CHECK(nodus_dht_ipc_sock_path(local_dir,sock,sizeof(sock))==0);
    CHECK(nodus_dht_ipc_listen(storage,sock)==0);
    uint8_t id[32]; uint64_t height;
    CHECK(!host.inter_status(host.ctx,id,&height)); /* no control/answer */
    nodus_key_t fp={{0x71}};
    uint8_t p[256],fr[264]; size_t n=0;
    CHECK(nodus_t2_presence_sync(1,&fp,1,p,sizeof(p),&n)==0);
    size_t fn=nodus_frame_encode(fr,sizeof(fr),p,(uint32_t)n); CHECK(fn);
    CHECK(host.inter_send(host.ctx,"127.0.0.1",24402,&receiver->identity.node_id,fr,fn)==-1);
    if(!external) ((chain_t *)core->chain)->known=false;
    for(unsigned i=0;i<30;++i) pump();
    CHECK(!host.inter_status(host.ctx,id,&height));
    CHECK(host.inter_send(host.ctx,"127.0.0.1",24402,&receiver->identity.node_id,fr,fn)==-1);
    CHECK(receiver->inter_tcp.count==0); /* no chain or witness => no dial */
    witness_t w={0};
    nodus_witness_ipc_handlers_t handlers={
        .dispatch_dnac=wdispatch,.cc_collect=wcollect,.status=wstatus,.roles=wroles,.ctx=&w
    };
    witness=nodus_witness_ipc_new(&handlers); CHECK(witness);
    CHECK(nodus_witness_ipc_sock_path(local_dir,sock,sizeof(sock))==0);
    CHECK(nodus_witness_ipc_listen(witness,sock)==0);
    if(!external) ((chain_t *)core->chain)->known=true;
    bool known=false;
    for(unsigned i=0;i<10000 && !known;++i) { pump(); known=host.inter_status(host.ctx,id,&height); }
    CHECK(known && height==1 && !memcmp(id,ci,32));
    bool va=false,st=false;
    for(unsigned i=0;i<10000 && host.inter_role(host.ctx,&receiver->identity.node_id,&va,&st)!=1;++i) pump();
    CHECK(host.inter_role(host.ctx,&receiver->identity.node_id,&va,&st)==1 && va && !st);
    CHECK(host.inter_send(host.ctx,"127.0.0.1",24402,&receiver->identity.node_id,fr,fn)==0);
    for(unsigned i=0;i<10000 && !max_open;++i) pump();
    CHECK(max_open==1);
    for(unsigned i=0;i<30;++i) pump();
    if(external) {
        CHECK(w.roles>0);
        CHECK(w.roles==2); /* independent whole-list query from core and storage */
    } else {
        CHECK(((chain_t *)core->chain)->roles>0);
        CHECK(w.statuses==0 && w.roles==0); /* no witness connection */
    }
    /* Queue a client batch miss; the batch opens its own admitted socket. */
    nodus_dht_peer_seen(dht,NODUS_DHT_PEER_ALIVE,&receiver->identity.node_id,
                         "127.0.0.1",24400,24402);
    nodus_dht_origin_t origin={NODUS_DHT_ORIGIN_CLIENT,0,1};
    nodus_dht_session_opened(dht,origin);
    uint8_t token[NODUS_SESSION_TOKEN_LEN]={0}; nodus_key_t key={{0x55}};
    CHECK(nodus_t2_get_batch_ex(7,token,&key,1,NULL,p,sizeof(p),&n)==0);
    nodus_tier2_msg_t msg={0}; CHECK(nodus_t2_decode(p,n,&msg)==0);
    nodus_dht_client_request(dht,0,&core->identity.node_id,&core->identity.pk,&msg);
    nodus_t2_msg_free(&msg);
    for(unsigned i=0;i<10000 && max_open<2;++i) pump();
    CHECK(max_open==2);
    for(unsigned i=0;i<10000;++i) {
        bool active=false;
        for(int j=0;j<NODUS_BF_MAX_BATCHES;++j) active |= dht->bf_state.batches[j].active;
        if(!active) break;
        pump();
    }
    for(int j=0;j<NODUS_BF_MAX_BATCHES;++j) CHECK(!dht->bf_state.batches[j].active);
    /* Arbitrarily many admission lookups do not ask for another list.
     * An absent fingerprint is a complete negative answer, with no query. */
    unsigned queries=external ? w.roles : ((chain_t *)core->chain)->roles;
    for(unsigned k=0;k<NODUS_TCP_MAX_CONNS+2u;++k) {
        nodus_key_t query_fp={{0}};
        memcpy(query_fp.bytes,&k,sizeof(k)); query_fp.bytes[63]=0xa9;
        va=st=false;
        CHECK(host.inter_role(host.ctx,&query_fp,&va,&st)==1 && !va && !st);
    }
    for(unsigned i=0;i<20;++i) pump();
    CHECK(queries==(external ? w.roles : ((chain_t *)core->chain)->roles));
    CHECK(nodus_dht_ipc_sock_path(local_dir,sock,sizeof(sock))==0);
    origin_queries(&host,sock);
    nodus_dht_stop(dht); nodus_dht_close(dht); free(dht);
    nodus_dht_ipc_free(storage);
    nodus_server_close(core); nodus_server_close(receiver);
    free(core); free(receiver); nodus_witness_ipc_free(witness); witness=NULL;
    char cmd[256]; snprintf(cmd,sizeof(cmd),"rm -rf %s %s",local_dir,remote_dir);
    CHECK(system(cmd)==0);
}
int main(void) { layout(false); layout(true); return 0; }
#else
/**
 * Nodus — Live Integration Test: Cross-Nodus Circuit (VPN Mesh Faz 1)
 *
 * Two in-process servers clustered together. User1 on server A opens
 * circuit to User2 on server B via fingerprint routing.
 */

#include "server/nodus_server.h"
#include "nodus/nodus.h"
#include "nodus/nodus_types.h"
#include "crypto/nodus_identity.h"
#include "consensus/nodus_cluster.h"
#include "core/nodus_routing.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

static int tests_run = 0;
static int tests_passed = 0;
#define TEST(name) do { tests_run++; printf("  [%d] %-48s ", tests_run, name); fflush(stdout); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while (0)

/* ── Server threads ─────────────────────────────────────────────── */

static nodus_server_t srv_a, srv_b;
/* Fixed ports 16000..16004/17000..17004: orchestrator runs serially.
 * Admission fixture: common test chain and validator role on both nodes.
 * Flags/environment: none. Existing per-process temporary dirs removed.
 * Delivery assertions still require a real authenticated cross-node session. */
static void fixture_tick(nodus_chain_backend_t *b) { (void)b; }
static bool fixture_pending(nodus_chain_backend_t *b) { (void)b; return false; }
static bool fixture_open(nodus_chain_backend_t *b) { (void)b; return true; }
static void fixture_status(nodus_chain_backend_t *b, nodus_t2_status_info_t *out) {
    (void)b; memset(out->chain_id,0x42,32); out->block_height=1;
}
static pthread_mutex_t fixture_lock=PTHREAD_MUTEX_INITIALIZER;
static nodus_key_t fixture_peers[2];
static size_t fixture_count;
static int fixture_roles(nodus_chain_backend_t *b, nodus_inter_role_list_t *out) {
    (void)b; pthread_mutex_lock(&fixture_lock);
    memset(out,0,sizeof(*out)); out->height=1;
    if (fixture_count==2) {
        memcpy(out->validators,fixture_peers,sizeof(fixture_peers)); out->validator_count=2;
        if (nodus_key_cmp(&out->validators[0],&out->validators[1])>0) {
            nodus_key_t swap=out->validators[0]; out->validators[0]=out->validators[1]; out->validators[1]=swap;
        }
    }
    pthread_mutex_unlock(&fixture_lock);
    return out->validator_count==2 ? 1 : 0;
}
static int fixture_port(nodus_chain_backend_t *b, bool *open) {
    (void)b; *open=false; return 0;
}
static void fixture_session_closed(nodus_chain_backend_t *b, nodus_tcp_conn_t *c) {
    (void)b; (void)c;
}
static void fixture_close(nodus_chain_backend_t *b) { free(b); }
static const nodus_chain_backend_ops_t fixture_ops={
    .tick=fixture_tick,.read_pending=fixture_pending,.status=fixture_status,
    .chain_open=fixture_open,.roles=fixture_roles,.listen_port=fixture_port,
    .session_closed=fixture_session_closed,.close=fixture_close
};
static int fixture_chain(const nodus_witness_host_t *host,
                           const nodus_witness_config_t *cfg,nodus_chain_backend_t **out) {
    (void)cfg; *out=calloc(1,sizeof(**out));
    if (!*out) return -2;
    pthread_mutex_lock(&fixture_lock);
    if (fixture_count<2) fixture_peers[fixture_count++]=host->identity->node_id;
    pthread_mutex_unlock(&fixture_lock);
    (*out)->ops=&fixture_ops; return 0;
}
static int fixture_server(nodus_server_t *srv, nodus_server_config_t *cfg) {
    nodus_server_backends_t be=nodus_server_backends_inproc;
    be.chain_open=fixture_chain; cfg->require_peer_auth=true;
    return nodus_server_init_ex(srv,cfg,&be);
}
/* srv_*_done: set by that server's thread once nodus_server_init has
 * RETURNED, success or failure; srv_*_ready: it succeeded. main waits for
 * both outcomes, not for a time budget: init runs the witness start checks
 * (the EVM precompile self-test loads the KZG setup), whose duration
 * depends on the host — the old 5000 ms budget failed with init still
 * running under `ctest -j2` (2026-10-05, Nodus EVM red-team 1 F2). A FAILED
 * init signals too, so it cannot hang this wait; an init that never returns
 * does (nodus/CMakeLists.txt sets no per-test TIMEOUT — bound it with
 * `ctest --timeout`), never a guessed number here. All
 * four flags are read and written only under init_lock; main sleeps on
 * init_cond. */
static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  init_cond = PTHREAD_COND_INITIALIZER;
static bool srv_a_ready = false, srv_a_done = false;
static bool srv_b_ready = false, srv_b_done = false;

static void srv_init_outcome(bool *done, bool *ready_flag, bool ready) {
    pthread_mutex_lock(&init_lock);
    *ready_flag = ready;
    *done = true;
    pthread_cond_broadcast(&init_cond);
    pthread_mutex_unlock(&init_lock);
}

static void *srv_a_thread(void *arg) {
    (void)arg;
    nodus_server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");
    cfg.udp_port = 16000;
    cfg.tcp_port = 16001;
    cfg.peer_port = 16002;
    cfg.ch_port = 16003;
    cfg.witness_port = 16004;
    cfg.require_peer_auth = true;
    snprintf(cfg.data_path, sizeof(cfg.data_path), "/tmp/nodus_cross_a_%d", getpid());
    char cmd[256]; snprintf(cmd, sizeof(cmd), "mkdir -p %s", cfg.data_path); system(cmd);
    if (fixture_server(&srv_a, &cfg) != 0) {
        fprintf(stderr, "srv_a init failed\n");
        srv_init_outcome(&srv_a_done, &srv_a_ready, false);
        return NULL;
    }
    srv_init_outcome(&srv_a_done, &srv_a_ready, true);
    nodus_server_run(&srv_a);
    nodus_server_close(&srv_a);
    snprintf(cmd, sizeof(cmd), "rm -rf %s", cfg.data_path); system(cmd);
    return NULL;
}

static void *srv_b_thread(void *arg) {
    (void)arg;
    nodus_server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");
    cfg.udp_port = 17000;
    cfg.tcp_port = 17001;
    cfg.peer_port = 17002;
    cfg.ch_port = 17003;
    cfg.witness_port = 17004;
    cfg.require_peer_auth = true;
    snprintf(cfg.data_path, sizeof(cfg.data_path), "/tmp/nodus_cross_b_%d", getpid());
    char cmd[256]; snprintf(cmd, sizeof(cmd), "mkdir -p %s", cfg.data_path); system(cmd);
    if (fixture_server(&srv_b, &cfg) != 0) {
        fprintf(stderr, "srv_b init failed\n");
        srv_init_outcome(&srv_b_done, &srv_b_ready, false);
        return NULL;
    }
    srv_init_outcome(&srv_b_done, &srv_b_ready, true);
    nodus_server_run(&srv_b);
    nodus_server_close(&srv_b);
    snprintf(cmd, sizeof(cmd), "rm -rf %s", cfg.data_path); system(cmd);
    return NULL;
}

/* ── Callbacks ─────────────────────────────────────────────────── */

typedef struct {
    uint8_t  received_data[65536];
    size_t   received_len;
    volatile bool got_data;
    volatile bool got_close;
    nodus_circuit_handle_t *inbound_handle;
    nodus_key_t inbound_peer_fp;
    volatile bool got_inbound;
} ctx_t;

static void on_data_cb(nodus_circuit_handle_t *h, const uint8_t *d, size_t n, void *u) {
    (void)h;
    ctx_t *c = (ctx_t *)u;
    if (n <= sizeof(c->received_data)) { memcpy(c->received_data, d, n); c->received_len = n; c->got_data = true; }
}
static void on_close_cb(nodus_circuit_handle_t *h, int r, void *u) { (void)h; (void)r; ((ctx_t *)u)->got_close = true; }
static void on_inbound_cb(struct nodus_client *cl, const nodus_key_t *peer_fp,
                           nodus_circuit_handle_t *h, void *u) {
    (void)cl;
    ctx_t *c = (ctx_t *)u;
    c->inbound_peer_fp = *peer_fp;
    c->inbound_handle = h;
    c->got_inbound = true;
    nodus_circuit_attach(h, on_data_cb, on_close_cb, u);
}
static bool wait_for(volatile bool *flag, int timeout_ms) {
    int e = 0; while (!*flag && e < timeout_ms) { struct timespec t = {0, 10*1000*1000}; nanosleep(&t, NULL); e += 10; }
    return *flag;
}
/* Observe server A through its client connection, on A's owner thread.
 * Stop after fifty consecutive replies with no newly online fingerprint;
 * an online remote entry is required, so local auth alone cannot pass.
 * No extra flags/environment or artifacts; this replaces the fixed sleep. */
static bool wait_for_remote_presence(nodus_client_t *client,
                                     const nodus_key_t *local, const nodus_key_t *remote) {
    const nodus_key_t fps[] = {*local, *remote};
    unsigned seen = 0, stalled = 0;
    while (stalled < 50) {
        nodus_presence_result_t result;
        if (nodus_client_presence_query(client, fps, 2, &result) != 0) return false;
        unsigned online = 0;
        for (int i = 0; result.entries && i < result.online_count; ++i) {
            if (!result.entries[i].online) continue;
            if (nodus_key_cmp(&result.entries[i].fp, local) == 0) online |= 1;
            if (result.entries[i].peer_index != 0 &&
                nodus_key_cmp(&result.entries[i].fp, remote) == 0) online |= 2;
        }
        nodus_client_free_presence_result(&result);
        if (online & 2) return true;
        if (online & ~seen) { seen |= online; stalled = 0; }
        else stalled++;
    }
    return false;
}

/* ── Main test ─────────────────────────────────────────────────── */

int main(void) {
    printf("=== Cross-Nodus Circuit Integration Test ===\n");

    pthread_t tid_a, tid_b;
    int prc = pthread_create(&tid_a, NULL, srv_a_thread, NULL);
    if (prc != 0) {
        fprintf(stderr, "FATAL: pthread_create (srv_a) failed: %s\n", strerror(prc));
        return 1;
    }
    prc = pthread_create(&tid_b, NULL, srv_b_thread, NULL);
    if (prc != 0) {
        fprintf(stderr, "FATAL: pthread_create (srv_b) failed: %s\n", strerror(prc));
        return 1;
    }

    /* Wait for BOTH servers' init outcomes (see srv_a_done) */
    pthread_mutex_lock(&init_lock);
    while (!srv_a_done || !srv_b_done)
        pthread_cond_wait(&init_cond, &init_lock);
    bool ready = srv_a_ready && srv_b_ready;
    pthread_mutex_unlock(&init_lock);
    if (!ready) { FAIL("servers not ready"); return 1; }
    struct timespec settle = {0, 200*1000*1000}; nanosleep(&settle, NULL);

    /* Manually cluster-peer the two servers (ALIVE state, no heartbeat wait) */
    nodus_cluster_add_peer(&srv_a.cluster, &srv_b.identity.node_id,
                            "127.0.0.1", 17000, 17002);
    srv_a.cluster.peers[0].state = NODUS_NODE_ALIVE;
    srv_a.cluster.peers[0].last_seen = (uint64_t)time(NULL);

    nodus_cluster_add_peer(&srv_b.cluster, &srv_a.identity.node_id,
                            "127.0.0.1", 16000, 16002);
    srv_b.cluster.peers[0].state = NODUS_NODE_ALIVE;
    srv_b.cluster.peers[0].last_seen = (uint64_t)time(NULL);

    /* Also add to routing tables — presence p_sync broadcasts to routing peers,
     * not cluster peers. tcp_port here is the inter-node port (UDP+2). The
     * routing table is the in-process DHT's (split S4). */
    nodus_peer_t rp_b = {0};
    rp_b.node_id = srv_b.identity.node_id;
    snprintf(rp_b.ip, sizeof(rp_b.ip), "127.0.0.1");
    rp_b.udp_port = 17000;
    rp_b.tcp_port = 17002;
    rp_b.last_seen = (uint64_t)time(NULL);
    nodus_routing_insert(&nodus_dht_backend_inproc_state(srv_a.dht)->routing, &rp_b);

    nodus_peer_t rp_a = {0};
    rp_a.node_id = srv_a.identity.node_id;
    snprintf(rp_a.ip, sizeof(rp_a.ip), "127.0.0.1");
    rp_a.udp_port = 16000;
    rp_a.tcp_port = 16002;
    rp_a.last_seen = (uint64_t)time(NULL);
    nodus_routing_insert(&nodus_dht_backend_inproc_state(srv_b.dht)->routing, &rp_a);

    /* Two user identities */
    nodus_identity_t id_u1, id_u2;
    uint8_t s1[32], s2[32];
    memset(s1, 0x33, sizeof(s1)); memset(s2, 0x44, sizeof(s2));
    nodus_identity_from_seed(s1, &id_u1);
    nodus_identity_from_seed(s2, &id_u2);

    /* User1 → server A (16001), User2 → server B (17001) */
    nodus_client_config_t cfg_a, cfg_b;
    memset(&cfg_a, 0, sizeof(cfg_a));
    strncpy(cfg_a.servers[0].ip, "127.0.0.1", 63);
    cfg_a.servers[0].port = 16001; cfg_a.server_count = 1; cfg_a.request_timeout_ms = 8000;
    memcpy(&cfg_b, &cfg_a, sizeof(cfg_a));
    cfg_b.servers[0].port = 17001;

    nodus_client_t cl_u1, cl_u2;
    memset(&cl_u1, 0, sizeof(cl_u1)); memset(&cl_u2, 0, sizeof(cl_u2));

    TEST("user1 connect to server A");
    if (nodus_client_init(&cl_u1, &cfg_a, &id_u1) != 0) { FAIL("init"); goto cleanup; }
    if (nodus_client_connect(&cl_u1) != 0) { FAIL("connect"); goto cleanup; }
    PASS();

    TEST("user2 connect to server B");
    if (nodus_client_init(&cl_u2, &cfg_b, &id_u2) != 0) { FAIL("init"); goto cleanup; }
    if (nodus_client_connect(&cl_u2) != 0) { FAIL("connect"); goto cleanup; }
    PASS();

    /* Force immediate presence_sync broadcast from both servers by resetting last_sync.
     * The server main loop calls nodus_presence_tick() every iteration. */
    srv_a.presence.last_sync = 0;
    srv_b.presence.last_sync = 0;

    /* ── User2 registers inbound callback ───────────────────────── */
    ctx_t ctx_u2; memset(&ctx_u2, 0, sizeof(ctx_u2));
    nodus_circuit_set_inbound_cb(&cl_u2, on_inbound_cb, &ctx_u2);

    /* ── User1 opens circuit to User2 (cross-nodus) ────────────── */
    TEST("user1 opens cross-nodus circuit to user2");
    if (!wait_for_remote_presence(&cl_u1, &id_u1.node_id, &id_u2.node_id)) {
        FAIL("server A did not report user2 online after consecutive polls without progress");
        goto cleanup;
    }
    ctx_t ctx_u1; memset(&ctx_u1, 0, sizeof(ctx_u1));
    nodus_circuit_handle_t *h_u1 = NULL;
    int rc = nodus_circuit_open(&cl_u1, &id_u2.node_id, on_data_cb, on_close_cb, &ctx_u1, &h_u1);
    if (rc != 0 || !h_u1) {
        char m[64]; snprintf(m, sizeof(m), "rc=%d", rc);
        FAIL(m); goto cleanup;
    }
    PASS();

    TEST("user2 receives inbound notification");
    if (!wait_for(&ctx_u2.got_inbound, 2000)) { FAIL("no inbound"); goto cleanup; }
    if (nodus_key_cmp(&ctx_u2.inbound_peer_fp, &id_u1.node_id) != 0) { FAIL("wrong fp"); goto cleanup; }
    PASS();

    /* ── Data exchange 1 KB u1→u2 ───────────────────────────────── */
    TEST("u1->u2 1KB through cross-nodus");
    uint8_t payload[1024];
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)(i & 0xFF);
    ctx_u2.got_data = false; ctx_u2.received_len = 0;
    if (nodus_circuit_send(h_u1, payload, sizeof(payload)) != 0) { FAIL("send"); goto cleanup; }
    if (!wait_for(&ctx_u2.got_data, 2000)) { FAIL("no data"); goto cleanup; }
    if (ctx_u2.received_len != sizeof(payload) || memcmp(ctx_u2.received_data, payload, sizeof(payload)) != 0) {
        FAIL("mismatch"); goto cleanup;
    }
    PASS();

    /* ── Data exchange u2→u1 ───────────────────────────────────── */
    TEST("u2->u1 1KB reverse cross-nodus");
    uint8_t payload2[1024];
    for (size_t i = 0; i < sizeof(payload2); i++) payload2[i] = (uint8_t)((i * 13) & 0xFF);
    ctx_u1.got_data = false; ctx_u1.received_len = 0;
    if (nodus_circuit_send(ctx_u2.inbound_handle, payload2, sizeof(payload2)) != 0) { FAIL("send"); goto cleanup; }
    if (!wait_for(&ctx_u1.got_data, 2000)) { FAIL("no data"); goto cleanup; }
    if (ctx_u1.received_len != sizeof(payload2) || memcmp(ctx_u1.received_data, payload2, sizeof(payload2)) != 0) {
        FAIL("mismatch"); goto cleanup;
    }
    PASS();

    /* ── Close propagation ────────────────────────────────────── */
    TEST("circuit close propagates cross-nodus");
    ctx_u2.got_close = false;
    nodus_circuit_close(h_u1);
    if (!wait_for(&ctx_u2.got_close, 2000)) { FAIL("no close"); goto cleanup; }
    PASS();

    /* ── E2E (Kyber1024) across two servers — closes gap G4 ─────── */
    /* The plaintext path above proves the relay forwards bytes cross-nodus.
     * This proves nodus_circuit_open_e2e's Kyber handshake + AES-256-GCM
     * survives the inter-node ri_open/ri_data forwarding (opaque `ect` relay),
     * i.e. the encrypted path two real users on two servers actually hit. */
    ctx_u2.got_inbound = false;
    ctx_u2.got_data = false;

    TEST("E2E: user1 opens encrypted cross-nodus circuit");
    nodus_circuit_handle_t *h_u1_e2e = NULL;
    rc = nodus_circuit_open_e2e(&cl_u1, &id_u2.node_id, id_u2.kyber_pk,
                                on_data_cb, on_close_cb, &ctx_u1, &h_u1_e2e);
    if (rc != 0 || !h_u1_e2e) { char m[64]; snprintf(m, sizeof(m), "rc=%d", rc); FAIL(m); goto cleanup; }
    if (!h_u1_e2e->e2e_active) { FAIL("originator e2e not active"); goto cleanup; }
    PASS();

    TEST("E2E: user2 inbound has encryption active");
    if (!wait_for(&ctx_u2.got_inbound, 2000)) { FAIL("no inbound"); goto cleanup; }
    if (!ctx_u2.inbound_handle || !ctx_u2.inbound_handle->e2e_active) { FAIL("inbound e2e not active"); goto cleanup; }
    PASS();

    TEST("E2E: u1->u2 encrypted 1KB cross-nodus");
    uint8_t e2e_pl[1024];
    for (size_t i = 0; i < sizeof(e2e_pl); i++) e2e_pl[i] = (uint8_t)((i * 7 + 1) & 0xFF);
    ctx_u2.got_data = false; ctx_u2.received_len = 0;
    if (nodus_circuit_send(h_u1_e2e, e2e_pl, sizeof(e2e_pl)) != 0) { FAIL("send"); goto cleanup; }
    if (!wait_for(&ctx_u2.got_data, 2000)) { FAIL("no data"); goto cleanup; }
    if (ctx_u2.received_len != sizeof(e2e_pl) || memcmp(ctx_u2.received_data, e2e_pl, sizeof(e2e_pl)) != 0) {
        FAIL("plaintext mismatch after decrypt"); goto cleanup;
    }
    PASS();

    TEST("E2E: u2->u1 encrypted reverse cross-nodus");
    uint8_t e2e_pl2[1024];
    for (size_t i = 0; i < sizeof(e2e_pl2); i++) e2e_pl2[i] = (uint8_t)((i * 29 + 5) & 0xFF);
    ctx_u1.got_data = false; ctx_u1.received_len = 0;
    if (nodus_circuit_send(ctx_u2.inbound_handle, e2e_pl2, sizeof(e2e_pl2)) != 0) { FAIL("send"); goto cleanup; }
    if (!wait_for(&ctx_u1.got_data, 2000)) { FAIL("no data"); goto cleanup; }
    if (ctx_u1.received_len != sizeof(e2e_pl2) || memcmp(ctx_u1.received_data, e2e_pl2, sizeof(e2e_pl2)) != 0) {
        FAIL("plaintext mismatch after decrypt"); goto cleanup;
    }
    PASS();

    TEST("E2E: encrypted circuit close propagates cross-nodus");
    ctx_u2.got_close = false;
    nodus_circuit_close(h_u1_e2e);
    if (!wait_for(&ctx_u2.got_close, 2000)) { FAIL("no close"); goto cleanup; }
    PASS();

cleanup:
    nodus_client_close(&cl_u1);
    nodus_client_close(&cl_u2);
    nodus_server_stop(&srv_a);
    nodus_server_stop(&srv_b);
    pthread_join(tid_a, NULL);
    pthread_join(tid_b, NULL);

    printf("\n=== Cross-Nodus Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
#endif
