#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct ngx_http_ta_rbnode_s ngx_http_ta_rbnode_t;

struct ngx_http_ta_rbnode_s {
    u_char                       color;
    unsigned                     len:16;
    ngx_queue_t                  queue;
    ngx_atomic_t                 req_total;
    ngx_atomic_t                 bytes_in;
    ngx_atomic_t                 bytes_out;
    u_char                       data[1];
};

typedef struct {
    ngx_array_t                 *monitor;
    ngx_array_t                 *display;
} ngx_http_ta_conf_t;

typedef struct {
    ngx_rbtree_t                 rbtree;
    ngx_rbtree_node_t            sentinel;
    ngx_queue_t                  queue;
} ngx_http_ta_shctx_t;

typedef struct {
    ngx_str_t                   *val;
    ngx_slab_pool_t             *shpool;
    ngx_http_ta_shctx_t         *sh;
    ngx_http_complex_value_t     value;
} ngx_http_ta_ctx_t;

#define NGX_HTTP_TA_REQ_TOTAL                                                   \
    offsetof(ngx_http_ta_rbnode_t, req_total)
#define NGX_HTTP_TA_BYTES_IN                                                    \
    offsetof(ngx_http_ta_rbnode_t, bytes_in)
#define NGX_HTTP_TA_BYTES_OUT                                                   \
    offsetof(ngx_http_ta_rbnode_t, bytes_out)

#define REQ_FIELD(node, offset)                                                 \
        ((ngx_atomic_t *) ((char *) node + offset))

static off_t    fields[3] = {
    NGX_HTTP_TA_REQ_TOTAL,
    NGX_HTTP_TA_BYTES_IN,
    NGX_HTTP_TA_BYTES_OUT
};

static ngx_str_t   s_unassoic_hosts = ngx_string("__unassoic__.__hosts__");

void ngx_http_ta_count(void *data, off_t offset, ngx_int_t incr);
static void *ngx_http_ta_create_main_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_ta_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_ta_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_ta_init_module(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_ta_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static void *ngx_http_ta_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_ta_merge_loc_conf(
        ngx_conf_t *cf, void *parent, void *child);
static void ngx_http_ta_rbtree_add_server_name(
        ngx_shm_zone_t *shm_zone, ngx_str_t *val);
static void ngx_http_ta_rbtree_insert(ngx_rbtree_node_t *temp,
        ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_http_ta_rbnode_t *ngx_http_ta_rbtree_lookup(
        ngx_shm_zone_t *shm_zone, ngx_str_t *val);
static char *ngx_http_ta_show(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_ta_show_handler(ngx_http_request_t *r);
static char *ngx_http_ta_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t    ngx_http_ta_commands[] = {

    { ngx_string("traffic_analysis_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
      ngx_http_ta_zone,
      0,
      0,
      NULL },

    { ngx_string("traffic_analysis_show"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ta_show,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t    ngx_http_ta_module_ctx = {
    NULL,                           /* preconfiguration */
    ngx_http_ta_init,               /* postconfiguration */

    ngx_http_ta_create_main_conf,   /* create main configuration */
    NULL,                           /* init main configuration */

    NULL,                           /* create server configuration */
    NULL,                           /* merge server configuration */

    ngx_http_ta_create_loc_conf,    /* create location configuration */
    ngx_http_ta_merge_loc_conf      /* merge location configuration */
};

ngx_module_t    ngx_http_traffic_analysis_module = {
    NGX_MODULE_V1,
    &ngx_http_ta_module_ctx,        /* module context */
    ngx_http_ta_commands,           /* module directives */
    NGX_HTTP_MODULE,                /* module type */
    NULL,                           /* init master */
    ngx_http_ta_init_module,        /* init module */
    NULL,                           /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};

void
ngx_http_ta_count(void *data, off_t offset, ngx_int_t incr)
{
    ngx_http_ta_rbnode_t    *node = data;

    (void) ngx_atomic_fetch_add(REQ_FIELD(node, offset), incr);
}

static void *
ngx_http_ta_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_ta_conf_t          *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_ta_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->monitor = NGX_CONF_UNSET_PTR;
    conf->display = NGX_CONF_UNSET_PTR;

    return conf;
}

static void *
ngx_http_ta_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_ta_conf_t          *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_ta_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->monitor = NGX_CONF_UNSET_PTR;
    conf->display = NGX_CONF_UNSET_PTR;

    return conf;
}

static char *
ngx_http_ta_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ta_conf_t          *conf = child;
    ngx_http_ta_conf_t          *prev = parent;

    ngx_conf_merge_ptr_value(conf->monitor, prev->monitor, NULL);
    ngx_conf_merge_ptr_value(conf->display, prev->display, NULL);

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_ta_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt             *h;
    ngx_http_core_main_conf_t       *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_ta_handler;

    return NGX_OK;
}

static char *
ngx_http_ta_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ssize_t                             size;
    ngx_str_t                          *value;
    ngx_shm_zone_t                     *shm_zone;
    ngx_http_ta_ctx_t                  *ctx;
    ngx_http_compile_complex_value_t    ccv;
    ngx_shm_zone_t                    **z;
    ngx_http_ta_conf_t                 *smcf;

    value = cf->args->elts;

    size = ngx_parse_size(&value[3]);
    if (size == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid zone size \"%V\"", &value[3]);
        return NGX_CONF_ERROR;
    }

    if (size < (ssize_t) (8 * ngx_pagesize)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "zone \"%V\" is too small", &value[1]);
        return NGX_CONF_ERROR;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_ta_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_script_variables_count(&value[2]) == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the value \"%V\" is a constant",
                           &value[2]);
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &ctx->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ctx->val = ngx_palloc(cf->pool, sizeof(ngx_str_t));
    if (ctx->val == NULL) {
        return NGX_CONF_ERROR;
    }
    *ctx->val = value[2];

    shm_zone = ngx_shared_memory_add(cf, &value[1], size,
                                     &ngx_http_traffic_analysis_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    /* 防止一个zone名称绑定到不同的key上 */
    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound to value \"%V\"",
                           &cmd->name, &value[1], ctx->val);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_ta_init_zone;
    shm_zone->data = ctx;

    smcf = ngx_http_conf_get_module_main_conf(cf,
      ngx_http_traffic_analysis_module);
    if (smcf->monitor != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    if (smcf->monitor == NGX_CONF_UNSET_PTR) {
        smcf->monitor = ngx_array_create(cf->pool, 1,
                                         sizeof(ngx_shm_zone_t *));
        if (smcf->monitor == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    z = ngx_array_push(smcf->monitor);
    if (z == NULL) {
        return NGX_CONF_ERROR;
    }
    *z = shm_zone;
    if (smcf->display != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }
    if (smcf->display == NGX_CONF_UNSET_PTR) {
        smcf->display= ngx_array_create(cf->pool, 1,
                                         sizeof(ngx_shm_zone_t *));
        if (smcf->display == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    z = ngx_array_push(smcf->display);
    if (z == NULL) {
        return NGX_CONF_ERROR;
    }
    *z = shm_zone;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_ta_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_ta_ctx_t           *ctx, *octx;

    octx = data;
    ctx = shm_zone->data;

    if (octx != NULL) {
        if (ngx_strcmp(ctx->val->data, octx->val->data) != 0) {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "traffic analysis \"%V\" uses the value str \"%V\" "
                          "while previously it used \"%V\"",
                          &shm_zone->shm.name, ctx->val, octx->val);
            return NGX_ERROR;
        }

        ctx->shpool = octx->shpool;
        ctx->sh = octx->sh;

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_ta_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_http_ta_rbtree_insert);

    ngx_queue_init(&ctx->sh->queue);

    return NGX_OK;
}

static ngx_int_t
ngx_http_ta_handler(ngx_http_request_t *r)
{
    ngx_str_t                   val;
    ngx_shm_zone_t             *z;
    ngx_shm_zone_t            **shm_zone;
    ngx_http_ta_ctx_t          *ctx;
    ngx_http_ta_conf_t         *smcf;
    ngx_http_ta_rbnode_t       *fnode;

    smcf = ngx_http_get_module_main_conf(r, ngx_http_traffic_analysis_module);
    if (smcf->monitor == NULL) {
        /*ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,*/
                      /*"traffic analysis can not find shared memory");*/
        return NGX_DECLINED;
    }
    if (smcf->monitor == NGX_CONF_UNSET_PTR) {
        /*ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,*/
                      /*"traffic analysis can not find shared memory");*/
        return NGX_DECLINED;
    }
    shm_zone = smcf->monitor->elts;
    z = shm_zone[0];
    if (z == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "traffic analysis can not find shared memory");
        return NGX_DECLINED;
    }
    ctx = z->data;
    if (ngx_http_complex_value(r, &ctx->value, &val) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "failed to reap value of \"%V\"", ctx->val);
        return NGX_DECLINED;
    }
    fnode = ngx_http_ta_rbtree_lookup(z, &val);
    if (fnode != NULL) {
        ngx_http_ta_count(fnode, NGX_HTTP_TA_REQ_TOTAL, 1);
        ngx_http_ta_count(fnode, NGX_HTTP_TA_BYTES_IN, r->connection->received);
        ngx_http_ta_count(fnode, NGX_HTTP_TA_BYTES_OUT, r->connection->sent);
    } else {
        /*ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,*/
                      /*"no server in conf \"%V\"",*/
                      /*&z->shm.name);*/
        fnode = ngx_http_ta_rbtree_lookup(z, &s_unassoic_hosts);
        if (fnode != NULL) {
            ngx_http_ta_count(fnode, NGX_HTTP_TA_REQ_TOTAL, 1);
            ngx_http_ta_count(fnode, NGX_HTTP_TA_BYTES_IN,
              r->connection->received);
            ngx_http_ta_count(fnode, NGX_HTTP_TA_BYTES_OUT,
              r->connection->sent);
        }
    }

    return NGX_DECLINED;
}

static char *
ngx_http_ta_show(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                    *value;
    ngx_http_core_loc_conf_t     *clcf;
    ngx_http_ta_conf_t           *slcf = conf;
    ngx_shm_zone_t               *shm_zone, **z;

    value = cf->args->elts;

    if (slcf->display != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    slcf->display = ngx_array_create(cf->pool, 1, sizeof(ngx_shm_zone_t *));
    if (slcf->display == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &value[1], 0,
      &ngx_http_traffic_analysis_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }
    z = ngx_array_push(slcf->display);
    if (z == NULL) {
        return NGX_CONF_ERROR;
    }
    *z = shm_zone;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_ta_show_handler;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_ta_show_handler(ngx_http_request_t *r)
{
    ngx_int_t                     rc;
    ngx_buf_t                    *b;
    ngx_uint_t                    i, j;
    ngx_array_t                  *display;
    ngx_chain_t                  *tl, *free, *busy;
    ngx_queue_t                  *q;
    ngx_shm_zone_t              **shm_zone;
    ngx_http_ta_ctx_t            *ctx;
    ngx_http_ta_conf_t           *slcf;
    ngx_http_ta_rbnode_t         *node;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_traffic_analysis_module);

    display = slcf->display;
    if (display == NULL) {
        r->headers_out.status = NGX_HTTP_NO_CONTENT;
        return ngx_http_send_header(r);
    }

    r->headers_out.status = NGX_HTTP_OK;
    ngx_http_clear_content_length(r);

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    shm_zone = display->elts;

    for (free = busy = NULL, i = 0; i < display->nelts; i++) {
        ctx = shm_zone[i]->data;

        for (q = ngx_queue_head(&ctx->sh->queue);
             q != ngx_queue_sentinel(&ctx->sh->queue);
             q = ngx_queue_next(q))
        {
            node = ngx_queue_data(q, ngx_http_ta_rbnode_t, queue);

            tl = ngx_chain_get_free_buf(r->pool, &free);
            if (tl == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            b = tl->buf;
            if (b->start == NULL) {
                b->start = ngx_pcalloc(r->pool, 512);
                if (b->start == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                b->end = b->start + 512;
            }

            b->last = b->pos = b->start;
            b->memory = 1;
            b->temporary = 1;

            b->last = ngx_slprintf(b->last, b->end, "%*s,",
                                   (size_t) node->len, node->data);

            for (j = 0; j < sizeof(fields) / sizeof(off_t); j++) {
                b->last = ngx_slprintf(b->last, b->end, "%uA,",
                                       *REQ_FIELD(node, fields[j]));
            }

            *(b->last - 1) = '\n';

            if (ngx_http_output_filter(r, tl) == NGX_ERROR) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ngx_chain_update_chains(
              r->pool, &free, &busy, &tl,
              (ngx_buf_tag_t) &ngx_http_traffic_analysis_module);
        }
    }

    tl = ngx_chain_get_free_buf(r->pool, &free);
    if (tl == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b = tl->buf;
    b->last_buf = 1;

    return ngx_http_output_filter(r, tl);
}


static ngx_http_ta_rbnode_t *
ngx_http_ta_rbtree_lookup(ngx_shm_zone_t *shm_zone, ngx_str_t *val)
{
    uint32_t                      hash;
    ngx_int_t                     rc;
    ngx_rbtree_node_t            *node, *sentinel;
    ngx_http_ta_ctx_t            *ctx;
    ngx_http_ta_rbnode_t         *rs;

    ctx = shm_zone->data;
    hash = ngx_crc32_short(val->data, val->len);
    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    ngx_shmtx_lock(&ctx->shpool->mutex);
    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }
        if (hash > node->key) {
            node = node->right;
            continue;
        }
        /* hash == node->key */
        rs = (ngx_http_ta_rbnode_t *) &node->color;
        rc = ngx_memn2cmp(val->data, rs->data, val->len, (size_t) rs->len);
        if (rc == 0) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return rs;
        }
        node = (rc < 0) ? node->left : node->right;
    }
    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NULL;
}

static void
ngx_http_ta_rbtree_insert(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t          **p;
    ngx_http_ta_rbnode_t        *rsn, *rsnt;

    for ( ;; ) {
        if (node->key < temp->key) {
            p = &temp->left;
        } else if (node->key > temp->key) {
            p = &temp->right;
        } else { /* node->key == temp->key */
            rsn = (ngx_http_ta_rbnode_t *) &node->color;
            rsnt = (ngx_http_ta_rbnode_t *) &temp->color;
            p = (ngx_memn2cmp(rsn->data, rsnt->data, rsn->len, rsnt->len) < 0)
                ? &temp->left : &temp->right;
        }
        if (*p == sentinel) {
            break;
        }
        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

static void
ngx_http_ta_rbtree_add_server_name(ngx_shm_zone_t *shm_zone, ngx_str_t *val)
{
    size_t                        size;
    uint32_t                      hash;
    ngx_int_t                     rc;
    ngx_rbtree_node_t            *node, *sentinel;
    ngx_http_ta_ctx_t            *ctx;
    ngx_http_ta_rbnode_t         *rs;

    ctx = shm_zone->data;
    hash = ngx_crc32_short(val->data, val->len);
    if (ctx->sh == NULL) {
        return;
    }
    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    ngx_shmtx_lock(&ctx->shpool->mutex);
    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }
        if (hash > node->key) {
            node = node->right;
            continue;
        }
        /* hash == node->key */
        rs = (ngx_http_ta_rbnode_t *) &node->color;
        rc = ngx_memn2cmp(val->data, rs->data, val->len, (size_t) rs->len);
        if (rc == 0) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return;
        }
        node = (rc < 0) ? node->left : node->right;
    }

    size = offsetof(ngx_rbtree_node_t, color)
         + offsetof(ngx_http_ta_rbnode_t, data)
         + val->len;

    node = ngx_slab_alloc_locked(ctx->shpool, size);
    if (node == NULL) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return;
    }

    node->key = hash;
    rs = (ngx_http_ta_rbnode_t *) &node->color;
    rs->len = val->len;
    ngx_memcpy(rs->data, val->data, val->len);
    ngx_rbtree_insert(&ctx->sh->rbtree, node);
    ngx_queue_insert_head(&ctx->sh->queue, &rs->queue);

    ngx_shmtx_unlock(&ctx->shpool->mutex);
}

static ngx_int_t
ngx_http_ta_init_module(ngx_cycle_t *cycle)
{
    ngx_http_core_main_conf_t       *hcmc;
    ngx_http_ta_conf_t              *smcf;
    ngx_shm_zone_t                 **shm_zone;
    ngx_shm_zone_t                  *z;
    ngx_http_core_srv_conf_t       **server_conf;
    ngx_uint_t                       i = 0;
    ngx_uint_t                       j = 0;

    hcmc = (ngx_http_core_main_conf_t *)
        ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);
    if (hcmc == NULL) {
        return NGX_ERROR;
    }
    server_conf = hcmc->servers.elts;
    if (server_conf == NULL) {
        return NGX_ERROR;
    }

    smcf = ngx_http_cycle_get_module_main_conf(cycle,
      ngx_http_traffic_analysis_module);
    if (smcf == NULL) {
        return NGX_OK;
    }
    if (smcf->monitor == NULL || smcf->monitor == NGX_CONF_UNSET_PTR) {
        smcf->monitor = NULL;
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                "traffic analysis does not enable");
        return NGX_OK;
    }
    shm_zone = smcf->monitor->elts;
    if (shm_zone == NULL || shm_zone == NGX_CONF_UNSET_PTR) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                "traffic analysis does not enable");
        return NGX_OK;
    }
    z = shm_zone[0];
    if (z == NULL) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                "traffic analysis does not enable");
        return NGX_OK;
    }

    ngx_http_ta_rbtree_add_server_name(z, &s_unassoic_hosts);
    for (i = 0; i < hcmc->servers.nelts; i++) {
        ngx_http_server_name_t *server_names = \
          server_conf[i]->server_names.elts;
        if (server_names != NULL) {
            for(j = 0; j < server_conf[i]->server_names.nelts; ++j) {
                if (server_names[j].name.len != 0) {
                    ngx_http_ta_rbtree_add_server_name(
                            z, &server_names[j].name);
                }
            }
        }
    }

    return NGX_OK;
}
