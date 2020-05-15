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
#include <fluent-bit/flb_network.h>
#include <msgpack.h>

#include "udp.h"
#include "udp_conn.h"
#include "udp_config.h"

/*
 * For a server event, the collection event means a new client have arrived, we
 * accept the connection and create a new UDP instance which will wait for
 * JSON map messages.
 */
static int in_udp_collect(struct flb_input_instance *in,
                          struct flb_config *config, void *in_context)
{
    int len;
    int address_str_len;
    char address_str[256];
    struct flb_in_udp_config *ctx = in_context;
    struct sockaddr_in address;
    socklen_t address_len = sizeof(struct sockaddr_in);

    len = recvfrom(ctx->server_fd, ctx->buf, ctx->buffer_size, 0, &address, &address_len);
    if (len < 0) {
        flb_errno();
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    /* get or set buffer */
    address_str_len = snprintf(address_str, 256, "%x:%x:%x", address.sin_family, address.sin_addr, address.sin_port);
    flb_hash_get(ctx->buf_table, address_str_len, );

    return 0;
}

/* Initialize plugin */
static int in_udp_init(struct flb_input_instance *in,
                      struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_udp_config *ctx;
    (void) data;

    /* Allocate space for the configuration */
    ctx = udp_config_init(in);
    if (!ctx) {
        return -1;
    }
    ctx->ins = in;

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Create UDP server */
    ctx->server_fd = flb_net_server_udp(ctx->udp_port, ctx->listen);
    if (ctx->server_fd > 0) {
        flb_plg_info(ctx->ins, "listening on %s:%s", ctx->listen, ctx->udp_port);
    }
    else {
        flb_plg_error(ctx->ins, "could not bind address %s:%s. Aborting",
                      ctx->listen, ctx->udp_port);
        udp_config_destroy(ctx);
        return -1;
    }
    flb_net_socket_nonblocking(ctx->server_fd);

    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_socket(in,
                                         in_udp_collect,
                                         ctx->server_fd,
                                         config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector for IN_UDP input plugin");
        udp_config_destroy(ctx);
        return -1;
    }

    return 0;
}

static int in_udp_exit(void *data, struct flb_config *config)
{
    struct flb_in_udp_config *ctx = data;

    flb_socket_close(ctx->server_fd);
    flb_free(ctx->buf);

    udp_config_destroy(ctx);

    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_udp_plugin = {
    .name         = "udp",
    .description  = "UDP",
    .cb_init      = in_udp_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = NULL,
    .cb_resume    = NULL,
    .cb_exit      = in_udp_exit,
    .flags        = FLB_INPUT_NET,
};
