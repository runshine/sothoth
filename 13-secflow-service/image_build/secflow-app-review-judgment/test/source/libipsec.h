/* Shared type definitions — recovered from libipsec.so */

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct __attribute__((packed)) {
    uint8_t event_type;          /* +0x00 */
    uint8_t reserved_01;         /* +0x01 */
    uint16_t text_length;        /* +0x02 */
    uint16_t prefix_length;      /* +0x04 */
    char text[250];              /* +0x06 */
} IpsecBlackboxRecord;

typedef struct __attribute__((packed)) {
    uint16_t current_index;          /* +0x00 */
    uint16_t reserved_02;            /* +0x02 */
    uint16_t max_records;            /* +0x04 */
    uint16_t prefix_format_errors;   /* +0x06 */
    uint16_t record_overflow_errors; /* +0x08 */
    uint16_t reserved_0A;            /* +0x0A */
    IpsecBlackboxRecord records[100];/* +0x0C */
} IpsecBlackboxBuffer;

typedef struct __attribute__((packed)) {
    uint8_t type;                /* +0x00 */
    uint8_t reserved_01[7];      /* +0x01 */
    void *value;                 /* +0x08 */
} IpsecCfgAttrEntry;

typedef struct __attribute__((packed)) {
    IpsecCfgAttrEntry *entries;  /* +0x00 */
    uint32_t requested_records;  /* +0x08 */
    uint64_t continuation_cookie;/* +0x0C */
    uint16_t reserved_14;        /* +0x14 */
    uint16_t display_mode;       /* +0x16 */
    uint8_t attribute_count;     /* +0x18 */
} IpsecDisplayRequest;

typedef struct __attribute__((packed)) {
    uint32_t first_id;           /* +0x00 */
    uint32_t second_id;          /* +0x04 */
    uint64_t continuation_cookie;/* +0x08 */
    uint32_t flags;              /* +0x10 */
    uint32_t max_records;        /* +0x14 */ /* corrected in batch 2 */
    uint16_t display_mode;       /* +0x18 */ /* corrected in batch 2 */
    uint16_t reserved_1A;        /* +0x1A */ /* corrected in batch 2 */
} IpsecDisplayQueryState;

typedef struct __attribute__((packed)) {
    uint32_t first_id;           /* +0x00 */
    uint32_t flags;              /* +0x04 */
    uint64_t continuation_cookie;/* +0x08 */
    uint32_t max_records;        /* +0x10 */
    uint16_t display_mode;       /* +0x14 */
    uint16_t reserved_16;        /* +0x16 */
} IpsecComponentDisplayQueryState;

typedef struct __attribute__((packed)) {
    uint32_t value;
    uint32_t has_more;
} IpsecContinuationToken;

typedef struct __attribute__((packed)) {
    uint32_t record_count;       /* +0x00 */
    void *records;               /* +0x04 */
    uint16_t record_size;        /* +0x0C */
    uint16_t reserved_0E;        /* +0x0E */
    void *continuation_token;    /* +0x10 */
    uint16_t continuation_token_size; /* +0x18 */
} IpsecDisplayResult;

typedef struct __attribute__((packed)) {
    IpsecCfgAttrEntry *entries;  /* +0x00 */
    uint32_t query_count;        /* +0x08 */
    uint64_t option_data;        /* +0x0C */
    uint16_t option_size;        /* +0x14 */
    uint16_t atom_opcode;        /* +0x16 */
    uint8_t condition_count;     /* +0x18 */
    uint8_t reserved_19[3];      /* +0x19 */
} IpsecAppcfgQueryRequest;

typedef struct __attribute__((packed)) {
    uint32_t record_count;       /* +0x00 */
    void *records;               /* +0x04 */
    uint16_t record_size;        /* +0x0C */
    uint16_t reserved_0E;        /* +0x0E */
    void *option_data;           /* +0x10 */
    uint16_t option_size;        /* +0x18 */
    uint8_t reserved_1A[2];      /* +0x1A */
} IpsecAppcfgQueryResult;

typedef void (*IpsecDispatchHandler)(int64_t, int64_t);
typedef int64_t (*IpsecGetHandler)(int64_t, int64_t, unsigned int *);
typedef int64_t (*IpsecBackupHandler)(int64_t, int64_t, void *); /* added in batch 15 */

typedef struct __attribute__((packed)) {
    uint16_t service_type;              /* +0x00, added in batch 15 */
    uint16_t subservice_type;           /* +0x02, added in batch 15 */
    void *prepare_send_handler;         /* +0x04, uncertain, added in batch 15 */
    IpsecBackupHandler batch_handler;   /* +0x0C, added in batch 15 */
    IpsecBackupHandler realtime_handler;/* +0x14, added in batch 15 */
} IpsecServiceBackupCb;

typedef struct {
    uint64_t interval_and_flags;
    uint64_t arg0;
    int arg1;
} IpsecTimerRequest;

typedef struct {
    uint64_t interval_and_flags;
    int interval_ms;
} IpsecTimerInstanceDesc; /* added in batch 14 */

typedef struct __attribute__((packed)) {
    uint64_t ptr;
    int32_t len;
} IpsecSockMsgBufDesc; /* added in batch 20 */

typedef struct __attribute__((packed)) {
    uint32_t ipsec_cid;
    uint32_t sock_cid;
} IpsecSockCidPair; /* added in batch 20 */

typedef struct __attribute__((packed)) {
    uint64_t word0;
    uint64_t word1;
    int32_t word2;
} IpsecSockTraceRecord; /* added in batch 20 */

typedef struct __attribute__((packed)) {
    uint8_t reserved_00[40];
    void *payload;               /* +0x28 */
} AvlFindResult;

typedef struct __attribute__((packed)) {
    uint32_t sa_id;              /* +0x00 */
    uint8_t avl_node[24];        /* +0x04 */
    int16_t left_index;          /* +0x1C */
    int16_t right_index;         /* +0x1E */
} IpsecSaRefEntry;

typedef struct __attribute__((packed)) {
    uint8_t reserved_00[40];
    void *payload;               /* +0x28 */
    uint8_t reserved_30[1436]; /* corrected in batch 2 */
    uint8_t sa_ref_enabled;      /* +0x5CC */
    uint8_t reserved_5CD[3];
    uint8_t sa_ref_tree[24];     /* +0x5D0 */
    uint8_t reserved_5E8[16];
    uint32_t sa_ref_count;       /* +0x5F8 */
} IpsecVrEntry;

typedef struct __attribute__((packed)) {
    char name[16];
    uint32_t esp_auth_index;
    uint32_t esp_encr_index;
    uint32_t transport_index;
    uint32_t ah_auth_index;
    uint32_t encap_index;
    uint32_t locator_key;
    uint32_t proposal_value;
} IpsecProposalConfigMsg;

typedef struct __attribute__((packed)) {
    char name[16];
    uint32_t proposal_value;
    int32_t ah_auth_flags;
    int32_t esp_flags;
    int16_t transport_mode;
    uint8_t encap_mode;
    uint8_t reserved_1F;
} IpsecLibProposalSpec;

typedef struct __attribute__((packed)) {
    char name[16];
    uint32_t proposal_id;        /* +0x10 */
    uint32_t ah_auth_flags;      /* +0x14 */
    uint32_t esp_flags;          /* +0x18 */
    uint16_t transport_flags;    /* +0x1C */
    uint8_t encap_flag;          /* +0x1E */
    uint8_t reserved_1F;         /* +0x1F */
} IpsecLibProposalRecord;

typedef struct __attribute__((packed)) {
    uint8_t bytes[3920];
} IpsecSaLibConfig;

typedef struct __attribute__((packed)) {
    uint32_t component_type;
    uint32_t pid;
} IpsecPidMessage;

typedef struct __attribute__((packed)) {
    uint32_t component_type;
    uint32_t ldm_id;
    uint32_t reserved_08[2];
    uint32_t fenode_id;
} IpsecFeNodePidMessage;

typedef struct __attribute__((packed)) {
    uint32_t component_type;
    uint32_t reserved_04[3];
    uint32_t port_group_id;
    uint32_t fenode_id;
} IpsecPortGrpPidMessage;

typedef struct __attribute__((packed)) {
    uint8_t reserved_000[4];
    uint32_t debug_id;               /* +0x004 */
    uint8_t reserved_008[36];
    uint64_t cfg_mem_pool;           /* +0x02C */
    uint8_t reserved_034[16];
    uint64_t blackbox_mem_pool;      /* +0x044 */
    uint8_t reserved_04C[56];
    uint32_t ha_subscription_state;  /* +0x084 */
    uint32_t pp6_pid;                /* +0x088 */
    uint32_t pp6_pid_valid;          /* +0x08C */
    uint8_t reserved_090[52];
    uint32_t pp4_pid;                /* +0x0C4 */
    uint32_t pp4_pid_valid;          /* +0x0C8 */
    uint8_t reserved_0CC[187];
    uint8_t debug_enabled_secondary; /* +0x187 */
    uint8_t debug_enabled_primary;   /* +0x188 */
    uint8_t reserved_189[23];
    uint64_t ssp_handle;             /* +0x1A0 */
    char debug_text[560];            /* +0x1A8 */
    uint32_t deployment_location;    /* +0x3D8 */
    uint8_t reserved_3DC[260];
    uint32_t packet_total;           /* +0x4E0 */
    uint32_t packet_stats_start;     /* +0x4E4 */
    uint8_t reserved_4E8[112];
    IpsecBlackboxBuffer *blackbox;   /* +0x558 */
} IpsecContext;
