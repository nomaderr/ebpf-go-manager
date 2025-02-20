// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// Error code for blocking
#define EPERM 1

// Max length for directory/file name
#define MAX_NAME_LEN 64

// Keys for blocking specific paths
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

/**
 * Helper function to compare a dentry name with a constant string.
 * eBPF doesn't allow normal strcmp, so we manually compare characters.
 */
static __inline bool name_equals(const char *name, const char *pattern) {
    // Compare character by character
    for (int i = 0; i < MAX_NAME_LEN; i++) {
        if (name[i] != pattern[i]) {
            return false;
        }
        // If both ended in '\\0' at the same time
        if (name[i] == '\0') {
            return true;
        }
    }
    return false;
}

SEC("lsm/inode_create")
int BPF_PROG(block_file_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
    // We'll walk up the dentry chain to see if we find /etc/test, /tmp, or /var/log
    struct dentry *current = dentry;
    #pragma unroll  // unroll helps with eBPF limits, but limit the iteration count
    for (int depth = 0; depth < 20; depth++) {
        if (!current) {
            break; // Reached the top (NULL parent)
        }

        // Read the name of the current dentry
        char current_name[MAX_NAME_LEN];
        bpf_probe_read_kernel_str(current_name, sizeof(current_name),
                                  BPF_CORE_READ(current, d_name.name));

        // 1) Check for /tmp
        // If current_name == \"tmp\", then check if block is enabled for BLOCK_TMP
        if (name_equals(current_name, "tmp")) {
            u32 key = BLOCK_TMP;
            u32 *val = bpf_map_lookup_elem(&path_block_map, &key);
            if (val && *val == 1) {
                bpf_printk("Blocked file creation in /tmp (anywhere under /tmp): %s\\n", current_name);
                return -EPERM;
            }
        }

        // 2) Check for /var/log
        // Actually we want \"log\" with parent \"var\".
        if (name_equals(current_name, "log")) {
            // Let's peek at the parent of \"log\" to see if it's \"var\"
            struct dentry *parent = BPF_CORE_READ(current, d_parent);
            if (parent) {
                char parent_name[MAX_NAME_LEN];
                bpf_probe_read_kernel_str(parent_name, sizeof(parent_name),
                                          BPF_CORE_READ(parent, d_name.name));
                if (name_equals(parent_name, "var")) {
                    // if block is enabled
                    u32 key = BLOCK_VAR_LOG;
                    u32 *val = bpf_map_lookup_elem(&path_block_map, &key);
                    if (val && *val == 1) {
                        bpf_printk("Blocked file creation under /var/log\\n");
                        return -EPERM;
                    }
                }
            }
        }

        // 3) Check for /etc/test
        // That means current_name == \"test\" and its parent == \"etc\".
        if (name_equals(current_name, "test")) {
            struct dentry *parent = BPF_CORE_READ(current, d_parent);
            if (parent) {
                char parent_name[MAX_NAME_LEN];
                bpf_probe_read_kernel_str(parent_name, sizeof(parent_name),
                                          BPF_CORE_READ(parent, d_name.name));
                if (name_equals(parent_name, "etc")) {
                    u32 key = BLOCK_ETC_TEST;
                    u32 *val = bpf_map_lookup_elem(&path_block_map, &key);
                    if (val && *val == 1) {
                        bpf_printk("Blocked file creation under /etc/test\\n");
                        return -EPERM;
                    }
                }
            }
        }

        // Move up one directory
        current = BPF_CORE_READ(current, d_parent);
    }

    // If we get here, none of the blocked paths were found in the ancestry -> allow
    return 0;
}


/*

ecli run package.json
bpftool map show
bpftool map pin id <found_id> /sys/fs/bpf/path_block_map
for /etc/test
sudo bpftool map update pinned /sys/fs/bpf/path_block_map \
  key 01 00 00 00 \
  value 01 00 00 00

*/