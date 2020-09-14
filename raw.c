#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "raw.h"

#include "tap.h"

static int
rawdev_tap_open(struct rawdev *dev){
    dev->priv = tap_dev_open(dev->name);
    return dev->priv ? 0 : -1;
}

static void
rawdev_tap_close(struct rawdev *dev){
    tap_dev_close(dev->priv);
}

static void
rawdev_tap_rx (struct rawdev *dev, void (*callback)(uint8_t *, size_t, void *), void *arg, int timeout) {
    tap_dev_rx(dev, callback, arg, timeout);
}

static ssize_t
rawdev_tap_tx (struct rawdev *dev, const uint8_t *buf, size_t len) {
    return tap_dev_tx(dev, buf, len);
}

static int
rawdev_tap_addr (struct rawdev *dev, uint8_t *dst, size_t size) {
    return tap_dev_addr(dev, dst, size);
}

struct rawdev_ops tap_dev_ops = {
    .open = rawdev_tap_open,
    .close = rawdev_tap_close,
    .rx = rawdev_tap_rx,
    .tx = rawdev_tap_tx,
    .addr = rawdev_tap_addr
};

struct rawdev *
rawdev_alloc (uint8_t type, char *name){
    struct rawdev *raw;
    struct rawdev_ops *ops;

    switch(type) {
        case RAWDEV_TYPE_TAP:
            ops = &tap_dev_ops;
            break;
        default:
            fprintf(stderr, "unsupported raw device type (%u)\n", type);
            return NULL;
    }
    raw = malloc(sizeof(struct rawdev));
    if(!raw){
        fprintf(stderr, "malloc: failure\n");
        return NULL;
    }
    raw->type = type;
    raw->name = name;
    raw->ops = ops;
    raw->priv = NULL;
    return raw;
}
