// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";


#define EPERM 1


#define MAX_NAME_LEN 64


enum path_keys {
    BLOCK_ETC_TEST = 1,
    BLOCK_TMP,
    BLOCK_VAR_LOG,
};


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 3);
} path_block_map SEC(".maps");


SEC("lsm/inode_create")
int BPF_PROG(block_file_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{

    char name[MAX_NAME_LEN];
    char parent_name[MAX_NAME_LEN];


    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    struct dentry *parent = BPF_CORE_READ(dentry, d_parent);

    bpf_probe_read_kernel_str(name, sizeof(name), d_name.name);
    bpf_probe_read_kernel_str(parent_name, sizeof(parent_name), BPF_CORE_READ(parent, d_name.name));


    if (parent_name[0] == 't' && parent_name[1] == 'e' &&
        parent_name[2] == 's' && parent_name[3] == 't' &&
        parent_name[4] == '\0') {

       
        struct dentry *grandparent = BPF_CORE_READ(parent, d_parent);
        char grandparent_name[MAX_NAME_LEN];
        bpf_probe_read_kernel_str(grandparent_name, sizeof(grandparent_name),
                                  BPF_CORE_READ(grandparent, d_name.name));

        if (grandparent_name[0] == 'e' && grandparent_name[1] == 't' &&
            grandparent_name[2] == 'c' && grandparent_name[3] == '\0') {

         
            u32 key = BLOCK_ETC_TEST;
            u32 *val = bpf_map_lookup_elem(&path_block_map, &key);
            if (val && *val == 1) {
                bpf_printk("Blocked file creation in /etc/test: %s\n", name);
                return -EPERM;
            }
        }
    }


    if (parent_name[0] == 't' && parent_name[1] == 'm' &&
        parent_name[2] == 'p' && parent_name[3] == '\0') {
        
        u32 key = BLOCK_TMP;
        u32 *val = bpf_map_lookup_elem(&path_block_map, &key);
        if (val && *val == 1) {
            bpf_printk("Blocked file creation in /tmp: %s\n", name);
            return -EPERM;
        }
    }


    if (parent_name[0] == 'l' && parent_name[1] == 'o' &&
        parent_name[2] == 'g' && parent_name[3] == '\0') {


        struct dentry *grandparent = BPF_CORE_READ(parent, d_parent);
        char grandparent_name[MAX_NAME_LEN];
        bpf_probe_read_kernel_str(grandparent_name, sizeof(grandparent_name),
                                  BPF_CORE_READ(grandparent, d_name.name));

        if (grandparent_name[0] == 'v' && grandparent_name[1] == 'a' &&
            grandparent_name[2] == 'r' && grandparent_name[3] == '\0') {

            u32 key = BLOCK_VAR_LOG;
            u32 *val = bpf_map_lookup_elem(&path_block_map, &key);
            if (val && *val == 1) {
                bpf_printk("Blocked file creation in /var/log: %s\n", name);
                return -EPERM;
            }
        }
    }


    return 0;
}
