/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_unescape.h>
#include <fluent-bit/flb_hash.h>

#include "udp.h"
#include "udp_conn.h"
#include "udp_config.h"

#include <stdlib.h>

struct flb_in_udp_config *udp_config_init(struct flb_input_instance *ins)
{
    int ret;
    int len;
    int max_clients;
    char port[16];
    char *out;
    const char *tmp;
    const char *buffer_size;
    const char *chunk_size;
    const char *max_clients_config;
    struct flb_in_udp_config *ctx;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_in_udp_config));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    ctx->format = FLB_UDP_FMT_JSON;

    /* Data format (expected payload) */
    tmp = flb_input_get_property("format", ins);
    if (tmp) {
        if (strcasecmp(tmp, "json") == 0) {
            ctx->format = FLB_UDP_FMT_JSON;
        }
        else if (strcasecmp(tmp, "none") == 0) {
            ctx->format = FLB_UDP_FMT_NONE;
        }
        else {
            flb_plg_error(ctx->ins, "unrecognized format value '%s'", tmp);
            flb_free(ctx);
            return NULL;
        }
    }

    /* String separator used to split records when using 'format none' */
    tmp = flb_input_get_property("separator", ins);
    if (tmp) {
        len = strlen(tmp);
        out = flb_malloc(len + 1);
        if (!out) {
            flb_errno();
            flb_free(ctx);
            return NULL;
        }
        ret = flb_unescape_string(tmp, len, &out);
        if (ret <= 0) {
            flb_plg_error(ctx->ins, "invalid separator");
            flb_free(out);
            flb_free(ctx);
            return NULL;
        }

        ctx->separator = flb_sds_create_len(out, ret);
        if (!ctx->separator) {
            flb_free(out);
            flb_free(ctx);
            return NULL;
        }
        flb_free(out);
    }
    if (!ctx->separator) {
        ctx->separator = flb_sds_create_len("\n", 1);
    }

    /* Listen interface (if not set, defaults to 0.0.0.0:5170) */
    flb_input_net_default_listener("0.0.0.0", 5170, ins);
    ctx->listen = ins->host.listen;
    snprintf(port, sizeof(port) - 1, "%d", ins->host.port);
    ctx->udp_port = flb_strdup(port);

    /* Chunk size */
    chunk_size = flb_input_get_property("chunk_size", ins);
    if (!chunk_size) {
        ctx->chunk_size = FLB_IN_UDP_CHUNK; /* 32KB */
    }
    else {
        /* Convert KB unit to Bytes */
        ctx->chunk_size  = (atoi(chunk_size) * 1024);
    }

    /* Buffer size */
    buffer_size = flb_input_get_property("buffer_size", ins);
    if (!buffer_size) {
        ctx->buffer_size = ctx->chunk_size;
    }
    else {
        /* Convert KB unit to Bytes */
        ctx->buffer_size  = (atoi(buffer_size) * 1024);
    }

    /* Max clients */
    max_clients_config = flb_input_get_property("max_clients", ins);
    if (!max_clients_config) {
        max_clients = 256;
    }
    else {
        max_clients = atoi(max_clients_config);
    }

    /* Buffer hash table */
    ctx->buf_table = flb_hash_create(FLB_HASH_EVICT_NONE, 1, max_clients);

    return ctx;
}

int udp_config_destroy(struct flb_in_udp_config *ctx)
{
    flb_sds_destroy(ctx->separator);
    flb_hash_destroy(ctx->buf_table);
    flb_free(ctx->udp_port);
    flb_free(ctx);

    return 0;
}
