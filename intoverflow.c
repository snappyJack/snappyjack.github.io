SYSCALL_DEFINE3(bpf,int, cmd,union bpf_attr __user*, uattr, unsigned int, size)      //首先调用这里
{
union bpf_attr attr = {};
int err;

if (sysctl_unprivileged_bpf_disabled && !
capable(CAP_SYS_ADMIN)
)
return -
EPERM;

err = bpf_check_uarg_tail_zero(uattr, sizeof(attr), size);
if (err)
return
err;
size = min_t(u32, size, sizeof(attr));

/* copy attributes from user space, may be less than sizeof(bpf_attr) */
if (copy_from_user(&attr, uattr, size) != 0)        //将uattr 拷贝到 &attr ,其中 uattr可控
return -
EFAULT;

err = security_bpf(cmd, &attr, size);
if (err < 0)
return
err;

switch (cmd) {
case BPF_MAP_CREATE:
err = map_create(&attr);            // ,控制cmd运行到这里,attr可控
break;
case BPF_MAP_LOOKUP_ELEM:
err = map_lookup_elem(&attr);
break;
case BPF_MAP_UPDATE_ELEM:
err = map_update_elem(&attr);
break;
case BPF_MAP_DELETE_ELEM:
err = map_delete_elem(&attr);
break;
case BPF_MAP_GET_NEXT_KEY:
err = map_get_next_key(&attr);
break;
case BPF_PROG_LOAD:
err = bpf_prog_load(&attr);
break;
case BPF_OBJ_PIN:
err = bpf_obj_pin(&attr);
break;
case BPF_OBJ_GET:
err = bpf_obj_get(&attr);
break;
case BPF_PROG_ATTACH:
err = bpf_prog_attach(&attr);
break;
case BPF_PROG_DETACH:
err = bpf_prog_detach(&attr);
break;
case BPF_PROG_QUERY:
err = bpf_prog_query(&attr, uattr);
break;
case BPF_PROG_TEST_RUN:
err = bpf_prog_test_run(&attr, uattr);
break;
case BPF_PROG_GET_NEXT_ID:
err = bpf_obj_get_next_id(&attr, uattr,
                          &prog_idr, &prog_idr_lock);
break;
case BPF_MAP_GET_NEXT_ID:
err = bpf_obj_get_next_id(&attr, uattr,
                          &map_idr, &map_idr_lock);
break;
case BPF_PROG_GET_FD_BY_ID:
err = bpf_prog_get_fd_by_id(&attr);
break;
case BPF_MAP_GET_FD_BY_ID:
err = bpf_map_get_fd_by_id(&attr);
break;
case BPF_OBJ_GET_INFO_BY_FD:
err = bpf_obj_get_info_by_fd(&attr, uattr);
break;
case BPF_RAW_TRACEPOINT_OPEN:
err = bpf_raw_tracepoint_open(&attr);
break;
case BPF_BTF_LOAD:
err = bpf_btf_load(&attr);
break;
case BPF_BTF_GET_FD_BY_ID:
err = bpf_btf_get_fd_by_id(&attr);
break;
case BPF_TASK_FD_QUERY:
err = bpf_task_fd_query(&attr, uattr);
break;
case BPF_MAP_LOOKUP_AND_DELETE_ELEM:
err = map_lookup_and_delete_elem(&attr);
break;
default:
err = -EINVAL;
break;
}

return
err;
}


#define BPF_MAP_CREATE_LAST_FIELD btf_value_type_id
/* called via syscall */
static int map_create(union bpf_attr *attr)             // 然后是这里   attr可控
{
    int numa_node = bpf_map_attr_numa_node(attr);
    struct bpf_map *map;
    int f_flags;
    int err;

    err = CHECK_ATTR(BPF_MAP_CREATE);
    if (err)
        return -EINVAL;

    f_flags = bpf_get_file_flag(attr->map_flags);
    if (f_flags < 0)
        return f_flags;

    if (numa_node != NUMA_NO_NODE &&
        ((unsigned int)numa_node >= nr_node_ids ||
         !node_online(numa_node)))
        return -EINVAL;

    /* find map type and init map: hashtable vs rbtree vs bloom vs ... */
    map = find_and_alloc_map(attr);                     // 第三步是这里  attr可控
    if (IS_ERR(map))
        return PTR_ERR(map);

    err = bpf_obj_name_cpy(map->name, attr->map_name);
    if (err)
        goto free_map_nouncharge;

    atomic_set(&map->refcnt, 1);
    atomic_set(&map->usercnt, 1);

    if (attr->btf_key_type_id || attr->btf_value_type_id) {
        struct btf *btf;

        if (!attr->btf_key_type_id || !attr->btf_value_type_id) {
            err = -EINVAL;
            goto free_map_nouncharge;
        }

        btf = btf_get_by_fd(attr->btf_fd);
        if (IS_ERR(btf)) {
            err = PTR_ERR(btf);
            goto free_map_nouncharge;
        }

        err = map_check_btf(map, btf, attr->btf_key_type_id,
                            attr->btf_value_type_id);
        if (err) {
            btf_put(btf);
            goto free_map_nouncharge;
        }

        map->btf = btf;
        map->btf_key_type_id = attr->btf_key_type_id;
        map->btf_value_type_id = attr->btf_value_type_id;
    }

    err = security_bpf_map_alloc(map);
    if (err)
        goto free_map_nouncharge;

    err = bpf_map_init_memlock(map);
    if (err)
        goto free_map_sec;

    err = bpf_map_alloc_id(map);
    if (err)
        goto free_map;

    err = bpf_map_new_fd(map, f_flags);
    if (err < 0) {
        /* failed to allocate fd.
         * bpf_map_put() is needed because the above
         * bpf_map_alloc_id() has published the map
         * to the userspace and the userspace may
         * have refcnt-ed it through BPF_MAP_GET_FD_BY_ID.
         */
        bpf_map_put(map);
        return err;
    }

    return err;

    free_map:
    bpf_map_release_memlock(map);
    free_map_sec:
    security_bpf_map_free(map);
    free_map_nouncharge:
    btf_put(map->btf);
    map->ops->map_free(map);
    return err;
}

static struct bpf_map *find_and_alloc_map(union bpf_attr *attr)     //第三步是这里 attr可控
{
    const struct bpf_map_ops *ops;
    u32 type = attr->map_type;      //先寻找type
    struct bpf_map *map;
    int err;

    if (type >= ARRAY_SIZE(bpf_map_types))
        return ERR_PTR(-EINVAL);
    type = array_index_nospec(type, ARRAY_SIZE(bpf_map_types));
    ops = bpf_map_types[type];                      //根据type的值寻找所对应的处理函数虚表 ,这个大概知道怎么找了      type = 0x17  调用queue_stack_map_alloc
    if (!ops)
        return ERR_PTR(-EINVAL);

    if (ops->map_alloc_check) {
        err = ops->map_alloc_check(attr);
        if (err)
            return ERR_PTR(err);
    }
    if (attr->map_ifindex)
        ops = &bpf_map_offload_ops;
    map = ops->map_alloc(attr);                    //调用虚函数
    if (IS_ERR(map))
        return map;
    map->ops = ops;
    map->map_type = type;
    return map;
}


static struct bpf_map *queue_stack_map_alloc(union bpf_attr *attr)              //通过调用虚函数运行到这里
{
    int ret, numa_node = bpf_map_attr_numa_node(attr);
    struct bpf_queue_stack *qs;
    u32 size, value_size;
    u64 queue_size, cost;

    size = attr->max_entries + 1;                       //整数溢出
    value_size = attr->value_size;

    queue_size = sizeof(*qs) + (u64) value_size * size;

    cost = queue_size;
    if (cost >= U32_MAX - PAGE_SIZE)
        return ERR_PTR(-E2BIG);

    cost = round_up(cost, PAGE_SIZE) >> PAGE_SHIFT;

    ret = bpf_map_precharge_memlock(cost);
    if (ret < 0)
        return ERR_PTR(ret);

    qs = bpf_map_area_alloc(queue_size, numa_node);     // 申请过小的块
    if (!qs)
        return ERR_PTR(-ENOMEM);

    memset(qs, 0, sizeof(*qs));

    bpf_map_init_from_attr(&qs->map, attr);             // 初始化函数

    qs->map.pages = cost;
    qs->size = size;

    raw_spin_lock_init(&qs->lock);

    return &qs->map;
}




*(int*)(&b)+1