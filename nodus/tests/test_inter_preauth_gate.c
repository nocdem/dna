/* Suite selection flag: -DNODUS_TEST_WITNESS_ROLE=1; ordinary target uses
 * the other branch. This only selects test fixtures, not protocol constants. */
#if defined(NODUS_TEST_WITNESS_ROLE)
/* Build plan 4.3: actual witness.sock whole-list requests for every admitted and
 * excluded status, list height, database fault => ok=false with empty arrays, and
 * control connections may coexist. Flags: NODUS_TEST_WITNESS_ROLE=1; also ASan/UBSan.
 * Environment: wrong-uid arm requires root and reports a skip otherwise.
 * No network ports; temporary Unix socket/directory and in-memory database
 * removed. Positive role and two-control checks prevent a dead listener
 * from passing. The wrong-uid arm temporarily relaxes file mode so it
 * specifically reaches SO_PEERCRED rather than failing at filesystem mode. */
#include "witness/nodus_witness_ipc.h"
#include "witness/nodus_witness.h"
#include "crypto/nodus_identity.h"
#include "protocol/nodus_cbor.h"
#include "transport/nodus_tcp.h"
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x); exit(1); } } while(0)
static nodus_identity_t id;
static bool answer_ok, answer_va, answer_st;
static nodus_inter_role_list_t answer_list;
static unsigned replies;
static void frame(nodus_tcp_conn_t *c,const uint8_t *p,size_t n,void *ctx) {
    (void)c; (void)ctx;
    CHECK(!nodus_inter_roles_decode(NODUS_WITNESS_IPC_Q_ROLES,p,n,&answer_list,&answer_ok));
    CHECK(!answer_ok || answer_list.height==17);
    answer_va=answer_st=false;
    nodus_inter_roles_lookup(&answer_list,&id.node_id,&answer_va,&answer_st);
    if (!answer_ok) CHECK(!answer_list.validator_count && !answer_list.storage_count);
    for (size_t i=1;i<answer_list.validator_count;++i)
        CHECK(nodus_key_cmp(&answer_list.validators[i-1],&answer_list.validators[i])<=0);
    for (size_t i=1;i<answer_list.storage_count;++i)
        CHECK(nodus_key_cmp(&answer_list.storage[i-1],&answer_list.storage[i])<=0);
    replies++;
}
static void query(nodus_witness_ipc_t *ipc,nodus_tcp_t *tcp,nodus_tcp_conn_t *c,
                    bool ok,bool va,bool st) {
    uint8_t buf[256]; cbor_encoder_t e; cbor_encoder_init(&e,buf,sizeof(buf));
    cbor_encode_map(&e,1);
    cbor_encode_cstr(&e,"q"); cbor_encode_cstr(&e,NODUS_WITNESS_IPC_Q_ROLES);
    unsigned before=replies;
    CHECK(!e.error && nodus_tcp_send(c,buf,cbor_encoder_len(&e))==0);
    for(unsigned i=0;i<1000 && replies==before;++i) {
        nodus_tcp_poll(tcp,0); nodus_witness_ipc_poll(ipc,1);
    }
    CHECK(replies==before+1 && answer_ok==ok && answer_va==va && answer_st==st);
}
static nodus_tcp_conn_t *control(nodus_tcp_t *tcp,const char *path) {
    nodus_tcp_conn_t *c=nodus_tcp_unix_connect(tcp,path,NODUS_TCP_UNIX_UID_SELF); CHECK(c);
    uint8_t buf[64]; cbor_encoder_t e; cbor_encoder_init(&e,buf,sizeof(buf));
    cbor_encode_map(&e,1); cbor_encode_cstr(&e,"q"); cbor_encode_cstr(&e,NODUS_WITNESS_IPC_Q_CTL);
    CHECK(nodus_tcp_send(c,buf,cbor_encoder_len(&e))==0); return c;
}
static void wrong_uid(nodus_witness_ipc_t *ipc,const char *dir,const char *path) {
    if(geteuid()!=0) { puts("SKIP: witness wrong-uid arm requires root"); return; }
    CHECK(chmod(dir,0755)==0 && chmod(path,0666)==0);
    int ready[2],done[2]; CHECK(pipe(ready)==0 && pipe(done)==0);
    pid_t child=fork(); CHECK(child>=0);
    if(!child) {
        close(ready[0]); close(done[1]);
        if(setgid(65534)!=0 || setuid(65534)!=0) _exit(2);
        int fd=socket(AF_UNIX,SOCK_STREAM,0); if(fd<0) _exit(3);
        struct sockaddr_un a={.sun_family=AF_UNIX};
        snprintf(a.sun_path,sizeof(a.sun_path),"%s",path);
        if(connect(fd,(struct sockaddr *)&a,sizeof(a))!=0) _exit(4);
        char b=1; if(write(ready[1],&b,1)!=1 || read(done[0],&b,1)!=1) _exit(5);
        ssize_t n=recv(fd,&b,1,MSG_DONTWAIT);
        bool rejected=n==0 || (n<0 && errno==ECONNRESET);
        close(fd); _exit(rejected ? 0 : 6);
    }
    close(ready[1]); close(done[0]); char b;
    CHECK(read(ready[0],&b,1)==1);
    for(unsigned i=0;i<20;++i) nodus_witness_ipc_poll(ipc,1);
    CHECK(write(done[1],&b,1)==1);
    int code; CHECK(waitpid(child,&code,0)==child && WIFEXITED(code) && WEXITSTATUS(code)==0);
    close(ready[0]); close(done[1]); CHECK(chmod(path,0600)==0 && chmod(dir,0700)==0);
}
int main(void) {
    CHECK(nodus_identity_generate(&id)==0);
    nodus_witness_t *w=calloc(1,sizeof(*w)); CHECK(w && sqlite3_open(":memory:",&w->db)==SQLITE_OK);
    CHECK(sqlite3_exec(w->db,"CREATE TABLE validators(pubkey BLOB,status INTEGER);"
        "CREATE TABLE v2_storage_nodes(node_fp BLOB,status INTEGER);"
        "CREATE TABLE blocks(height INTEGER); INSERT INTO blocks VALUES(17)",NULL,NULL,NULL)==SQLITE_OK);
    nodus_witness_ipc_handlers_t h; nodus_witness_ipc_handlers_for(w,&h);
    nodus_witness_ipc_t *ipc=nodus_witness_ipc_new(&h); CHECK(ipc);
    char dir[]="/tmp/nodus_role_wire_XXXXXX",path[160]; CHECK(mkdtemp(dir));
    CHECK(nodus_witness_ipc_sock_path(dir,path,sizeof(path))==0);
    CHECK(nodus_witness_ipc_listen(ipc,path)==0);
    nodus_tcp_t tcp; CHECK(nodus_tcp_init(&tcp,-1)==0); tcp.on_frame=frame;
    nodus_tcp_conn_t *c=control(&tcp,path), *second=control(&tcp,path);
    query(ipc,&tcp,c,true,false,false); query(ipc,&tcp,second,true,false,false);
    for(int kind=0;kind<2;++kind) for(int status=0;status<5;++status) {
        sqlite3_stmt *s=NULL;
        CHECK(sqlite3_prepare_v2(w->db,kind ? "INSERT INTO v2_storage_nodes VALUES(?,?)" :
            "INSERT INTO validators VALUES(?,?)",-1,&s,NULL)==SQLITE_OK);
        CHECK(sqlite3_bind_blob(s,1,kind ? id.node_id.bytes : id.pk.bytes,
                                 kind ? 64 : NODUS_PK_BYTES,SQLITE_STATIC)==SQLITE_OK);
        CHECK(sqlite3_bind_int(s,2,status)==SQLITE_OK);
        CHECK(sqlite3_step(s)==SQLITE_DONE && sqlite3_finalize(s)==SQLITE_OK);
        query(ipc,&tcp,c,true,!kind && (status==0 || status==1 || status==4),
                               kind && (status==1 || status==2));
        CHECK(sqlite3_exec(w->db,"DELETE FROM validators; DELETE FROM v2_storage_nodes",NULL,NULL,NULL)==SQLITE_OK);
    }
    for (unsigned i=0;i<DNAC_MAX_VALIDATORS;++i) {
        nodus_pubkey_t pk=id.pk; pk.bytes[0]^=(uint8_t)i;
        sqlite3_stmt *s=NULL;
        CHECK(sqlite3_prepare_v2(w->db,"INSERT INTO validators VALUES(?,0)",-1,&s,NULL)==SQLITE_OK);
        CHECK(sqlite3_bind_blob(s,1,pk.bytes,NODUS_PK_BYTES,SQLITE_TRANSIENT)==SQLITE_OK);
        CHECK(sqlite3_step(s)==SQLITE_DONE && sqlite3_finalize(s)==SQLITE_OK);
    }
    /* HF-9 WP4 (plan §8.7): the live storage rows reach the generation-6
     * capacity 1024; one more row exceeds the bound (below) */
    for (unsigned i=0;i<DNA_V2_STORAGE_SET_CAP;++i) {
        nodus_key_t fp=id.node_id; fp.bytes[0]^=(uint8_t)i; fp.bytes[1]^=(uint8_t)(i>>8);
        sqlite3_stmt *s=NULL;
        CHECK(sqlite3_prepare_v2(w->db,"INSERT INTO v2_storage_nodes VALUES(?,1)",-1,&s,NULL)==SQLITE_OK);
        CHECK(sqlite3_bind_blob(s,1,fp.bytes,NODUS_KEY_BYTES,SQLITE_TRANSIENT)==SQLITE_OK);
        CHECK(sqlite3_step(s)==SQLITE_DONE && sqlite3_finalize(s)==SQLITE_OK);
    }
    query(ipc,&tcp,c,true,true,true);
    CHECK(answer_list.validator_count==DNAC_MAX_VALIDATORS && answer_list.storage_count==DNA_V2_STORAGE_SET_CAP);
    CHECK(sqlite3_exec(w->db,"INSERT INTO validators SELECT * FROM validators LIMIT 1",NULL,NULL,NULL)==SQLITE_OK);
    query(ipc,&tcp,c,false,false,false);
    CHECK(sqlite3_exec(w->db,"DELETE FROM validators; INSERT INTO v2_storage_nodes SELECT * FROM v2_storage_nodes LIMIT 1",NULL,NULL,NULL)==SQLITE_OK);
    query(ipc,&tcp,c,false,false,false);
    CHECK(sqlite3_exec(w->db,"DROP TABLE validators",NULL,NULL,NULL)==SQLITE_OK);
    query(ipc,&tcp,c,false,false,false);
    wrong_uid(ipc,dir,path);
    nodus_tcp_close(&tcp); nodus_witness_ipc_free(ipc);
    CHECK(rmdir(dir)==0); sqlite3_close(w->db); free(w); nodus_identity_clear(&id); return 0;
}
#else
/* Build plan 4.3: No frame dispatched before open, including AUTHSIG trailing bytes; old hello closes; handshake deadline stays three seconds.
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
    happy_path(); trailing_authsig(); deadlines(); old_or_flood(false);
    nodus_identity_clear(&ids[0]); nodus_identity_clear(&ids[1]);
    return 0;
}
#endif
