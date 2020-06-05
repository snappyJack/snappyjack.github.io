static int map_update_elem(union bpf_attr *attr) {
    void __user
    *ukey = u64_to_user_ptr(attr->key);
    void __user
    *uvalue = u64_to_user_ptr(attr->value);
    int ufd = attr->map_fd; //用户id      可控
    struct bpf_map *map;
    void *key, *value;
    u32 value_size;
    struct fd f;
    int err;
    if (CHECK_ATTR(BPF_MAP_UPDATE_ELEM))
        return -EINVAL;

    f = fdget(ufd);    //用户id  -> 找到对应map
    map = __bpf_map_get(f);
    if (IS_ERR(map))
        return PTR_ERR(map);
    ......
    value_size = map->value_size;     //
    value = kmalloc(value_size, GFP_USER | __GFP_NOWARN); //根据value_size新建堆块
    if (copy_from_user(value, uvalue, value_size) != 0) // attr->value 处的值缓存到 attr->value
        goto free_value;
    ......
    //在map中找到存储的虚函数指针ops，然后根据ops调用相应的虚函数。
    err = map->ops->map_push_elem(map, value, attr->flags); //由虚表可知，map_push_elem真正调用了 queue_stack_map_push_elem()


}

/* Called from syscall or from eBPF program */
static int queue_stack_map_push_elem(struct bpf_map *map, void *value,
                                     u64 flags)
{
    struct bpf_queue_stack *qs = bpf_queue_stack(map);
    unsigned long irq_flags;
    int err = 0;
    void *dst;

    /* BPF_EXIST is used to force making room for a new element in case the
     * map is full
     */
    bool replace = (flags & BPF_EXIST);

    /* Check supported flags for queue and stack maps */
    if (flags & BPF_NOEXIST || flags > BPF_EXIST)
        return -EINVAL;

    raw_spin_lock_irqsave(&qs->lock, irq_flags);

    if (queue_stack_map_is_full(qs)) {
        if (!replace) {
            err = -E2BIG;
            goto out;
        }
        /* advance tail pointer to overwrite oldest element */
        if (unlikely(++qs->tail >= qs->size))
            qs->tail = 0;
    }

    dst = &qs->elements[qs->head * qs->map.value_size];
    memcpy(dst, value, qs->map.value_size);                  //堆溢出

    if (unlikely(++qs->head >= qs->size))
        qs->head = 0;

    out:
    raw_spin_unlock_irqrestore(&qs->lock, irq_flags);
    return err;
}

