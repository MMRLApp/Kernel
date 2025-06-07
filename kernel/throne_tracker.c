#include <linux/err.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/namei.h>

#include "allowlist.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "manager.h"
#include "throne_tracker.h"
#include "kernel_compat.h"
#include "apk_sign.h"

uid_t ksu_manager_uid = KSU_INVALID_UID;

#define SYSTEM_PACKAGES_LIST_PATH "/data/system/packages.list.tmp"

struct uid_data {
    struct list_head list;
    u32 uid;
    char package[KSU_MAX_PACKAGE_NAME];
};

// New struct for manager package entries
struct ksu_manager_package_entry {
    const char *name;
    const char *expected_hash; // SHA256 hash string, NULL to ignore signature check for this entry
    uint32_t expected_size;    // Signature size, ignored if expected_hash is NULL
};

static int get_pkg_from_apk_path(char *pkg, const char *path)
{
    int len = strlen(path);
    if (len >= KSU_MAX_PACKAGE_NAME || len < 1)
        return -1;

    const char *last_slash = NULL;
    const char *second_last_slash = NULL;

    int i;
    for (i = len - 1; i >= 0; i--) {
        if (path[i] == '/') {
            if (!last_slash) {
                last_slash = &path[i];
            } else {
                second_last_slash = &path[i];
                break;
            }
        }
    }

    if (!last_slash || !second_last_slash)
        return -1;

    const char *last_hyphen = strchr(second_last_slash, '-');
    if (!last_hyphen || last_hyphen > last_slash)
        return -1;

    int pkg_len = last_hyphen - second_last_slash - 1;
    if (pkg_len >= KSU_MAX_PACKAGE_NAME || pkg_len <= 0)
        return -1;

    // Copying the package name
    strncpy(pkg, second_last_slash + 1, pkg_len);
    pkg[pkg_len] = '\0';

    return 0;
}

static void crown_manager(const char *apk_path, struct list_head *uid_data, int *stop_flag)
{
    char pkg_name[KSU_MAX_PACKAGE_NAME];
    if (get_pkg_from_apk_path(pkg_name, apk_path) < 0) {
        pr_err("Failed to get package name from apk path: %s\n", apk_path);
        return;
    }

    static const struct ksu_manager_package_entry manager_pkgs[] = {
        { "com.dergoogler.mmrl", "102c2579a177579073dfc69bdf889ad04de9e7c53726a99d65873ec122183860", 0x033b },
        { "com.dergoogler.mmrl.wx", NULL, 0 }, 
        { "com.dergoogler.mmrl.debug", NULL, 0 },
        { "com.dergoogler.mmrl.wx.debug", NULL, 0 },
        { "com.rifsxd.ksunext", "79e590113c4c4c0c222978e413a5faa801666957b1212a328e46c00c69821bf7", 0x3e6 },
        { NULL, NULL, 0 }
    };

    pr_info("Checking manager candidate: %s (path: %s)\n", pkg_name, apk_path);

    for (int i = 0; manager_pkgs[i].name != NULL; i++) {
        if (strcmp(pkg_name, manager_pkgs[i].name) == 0) {
            pr_info("Package name match for %s. Verifying signature requirements.\n", pkg_name);
            bool signature_requirements_met = false;

            if (manager_pkgs[i].expected_hash == NULL) {
                // Signature check is explicitly ignored for this package entry
                signature_requirements_met = true;
                pr_info("Signature check IGNORED for manager package: %s\n", pkg_name);
            } else {
                // A specific signature is provided, check against it
                pr_info("Checking specific signature for %s: (size %u, hash %.10s...)\n",
                    pkg_name, manager_pkgs[i].expected_size, manager_pkgs[i].expected_hash);
                signature_requirements_met = is_apk_signed_with_key(apk_path,
                                            manager_pkgs[i].expected_hash,
                                            manager_pkgs[i].expected_size);
                if (signature_requirements_met) {
                    pr_info("Specific signature VERIFIED for manager package: %s\n", pkg_name);
                } else {
                    pr_info("Specific signature FAILED for manager package: %s\n", pkg_name);
                }
            }

            if (signature_requirements_met) {
                struct list_head *list = (struct list_head *)uid_data;
                struct uid_data *np;
                bool uid_found = false;

                list_for_each_entry (np, list, list) {
                    if (strncmp(np->package, pkg_name, KSU_MAX_PACKAGE_NAME) == 0) {
                        pr_info("Crowning manager: %s(uid=%d)\n", pkg_name, np->uid);
                        ksu_set_manager_uid(np->uid);
                        uid_found = true;
                        if (stop_flag) {
                            *stop_flag = 1; // Signal to stop searching further
                        }
                        break; 
                    }
                }
                if (!uid_found) {
                    pr_warn("Manager %s signature OK, but UID not found in packages.list cache.\n", pkg_name);
                }
                return; // Processed this candidate (crowned or UID not found), stop checking other manager_pkgs entries for this apk
            } else {
                // Package name matched, but signature requirements not met.
                // Stop processing this APK against other manager_pkgs entries.
                pr_info("Package %s matched but signature requirements not met.\n", pkg_name);
                return;
            }
        }
    }
    // If the loop completes, pkg_name did not match any entry in manager_pkgs.
    // No pr_info here to avoid spamming for every non-manager APK.
}


#define DATA_PATH_LEN 384 // 384 is enough for /data/app/<package>/base.apk

struct data_path {
    char dirpath[DATA_PATH_LEN];
    int depth;
    struct list_head list;
};

struct apk_path_hash {
    unsigned int hash;
    bool exists;
    struct list_head list;
};

static struct list_head apk_path_hash_list;

struct my_dir_context {
    struct dir_context ctx;
    struct list_head *data_path_list;
    char *parent_dir;
    void *private_data;
    int depth;
    int *stop;
    struct super_block* root_sb;
};
// https://docs.kernel.org/filesystems/porting.html
// filldir_t (readdir callbacks) calling conventions have changed. Instead of returning 0 or -E... it returns bool now. false means "no more" (as -E... used to) and true - "keep going" (as 0 in old calling conventions). Rationale: callers never looked at specific -E... values anyway. -> iterate_shared() instances require no changes at all, all filldir_t ones in the tree converted.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define FILLDIR_RETURN_TYPE bool
#define FILLDIR_ACTOR_CONTINUE true
#define FILLDIR_ACTOR_STOP false
#else
#define FILLDIR_RETURN_TYPE int
#define FILLDIR_ACTOR_CONTINUE 0
#define FILLDIR_ACTOR_STOP -EINVAL
#endif

FILLDIR_RETURN_TYPE my_actor(struct dir_context *ctx, const char *name,
                 int namelen, loff_t off, u64 ino,
                 unsigned int d_type)
{
    struct my_dir_context *my_ctx =
        container_of(ctx, struct my_dir_context, ctx);
    char dirpath[DATA_PATH_LEN];
    int err;
    struct path path;

    if (!my_ctx) {
        pr_err("Invalid context\n");
        return FILLDIR_ACTOR_STOP;
    }
    if (my_ctx->stop && *my_ctx->stop) {
        pr_info("Stop searching\n");
        return FILLDIR_ACTOR_STOP;
    }

    if (!strncmp(name, "..", namelen) || !strncmp(name, ".", namelen))
        return FILLDIR_ACTOR_CONTINUE; // Skip "." and ".."

    if (d_type == DT_DIR && namelen >= 8 && !strncmp(name, "vmdl", 4) &&
        !strncmp(name + namelen - 4, ".tmp", 4)) {
        pr_info("Skipping directory: %.*s\n", namelen, name);
        return FILLDIR_ACTOR_CONTINUE; // Skip staging package
    }

    if (snprintf(dirpath, DATA_PATH_LEN, "%s/%.*s", my_ctx->parent_dir,
             namelen, name) >= DATA_PATH_LEN) {
        pr_err("Path too long: %s/%.*s\n", my_ctx->parent_dir, namelen,
               name);
        return FILLDIR_ACTOR_CONTINUE;
    }

    err = kern_path(dirpath, 0, &path);

    if (err) {
        pr_err("get dirpath %s err: %d\n", dirpath, err);
        return FILLDIR_ACTOR_CONTINUE;
    }

    if (my_ctx->root_sb != path.dentry->d_inode->i_sb) {
        pr_info("skip cross fs: %s", dirpath);
        path_put(&path); // Release path obtained from kern_path
        return FILLDIR_ACTOR_CONTINUE;
    }
    path_put(&path); // Release path obtained from kern_path

    if (d_type == DT_DIR && my_ctx->depth > 0 &&
        (my_ctx->stop && !*my_ctx->stop)) {
        struct data_path *data = kmalloc(sizeof(struct data_path), GFP_ATOMIC);

        if (!data) {
            pr_err("Failed to allocate memory for %s\n", dirpath);
            return FILLDIR_ACTOR_CONTINUE;
        }

        strscpy(data->dirpath, dirpath, DATA_PATH_LEN);
        data->depth = my_ctx->depth - 1;
        list_add_tail(&data->list, my_ctx->data_path_list);
    } else {
        if ((namelen == 8) && (strncmp(name, "base.apk", namelen) == 0)) {
            struct apk_path_hash *pos_hash; // Renamed to avoid conflict
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
            unsigned int hash = full_name_hash(dirpath, strlen(dirpath));
#else
            unsigned int hash = full_name_hash(NULL, dirpath, strlen(dirpath));
#endif
            bool path_already_processed = false;
            list_for_each_entry(pos_hash, &apk_path_hash_list, list) {
                if (hash == pos_hash->hash) {
                    // pos_hash->exists = true; // This logic seems to be for re-scanning, might not be needed if we stop on first manager
                    path_already_processed = true; 
                    break;
                }
            }

            if (!path_already_processed) {
                // Call crown_manager directly. It will handle signature checks.
                // The old is_manager_apk call is removed from here.
                // crown_manager now takes stop_flag
                crown_manager(dirpath, my_ctx->private_data, my_ctx->stop);

                // Add to processed list if not already stopped (though stop might happen inside crown_manager)
                if (!(my_ctx->stop && *my_ctx->stop)) {
                    struct apk_path_hash *new_hash_entry = kmalloc(sizeof(struct apk_path_hash), GFP_ATOMIC);
                    if (new_hash_entry) {
                        new_hash_entry->hash = hash;
                        new_hash_entry->exists = true; // Mark as processed
                        list_add_tail(&new_hash_entry->list, &apk_path_hash_list);
                    }
                }
            }
        }
    }

    return FILLDIR_ACTOR_CONTINUE;
}

void search_manager(const char *path_str, int depth, struct list_head *uid_data)
{
    int i, stop = 0, err;
    struct list_head data_path_list;
    struct path kpath;
    struct super_block* root_sb;
    INIT_LIST_HEAD(&data_path_list);
    INIT_LIST_HEAD(&apk_path_hash_list); // Ensure this is initialized

    err = kern_path(path_str, 0, &kpath);

    if (err) {
        pr_err("get search root %s err: %d\n", path_str, err);
        return;
    }
    root_sb = kpath.dentry->d_inode->i_sb;
    path_put(&kpath); // Release path

    // Initialize APK cache list (exists flag is not used in the current my_actor logic for stopping early)
    // struct apk_path_hash *pos_apk_hash, *n_apk_hash;
    // list_for_each_entry(pos_apk_hash, &apk_path_hash_list, list) {
    // 	pos_apk_hash->exists = false;
    // }

    // First depth
    struct data_path *data_root = kmalloc(sizeof(struct data_path), GFP_KERNEL); // Use GFP_KERNEL if not in atomic context
    if (!data_root) {
        pr_err("Failed to allocate memory for root data_path\n");
        return;
    }
    strscpy(data_root->dirpath, path_str, DATA_PATH_LEN);
    data_root->depth = depth;
    list_add_tail(&data_root->list, &data_path_list);


    for (i = depth; i >= 0 && !stop; i--) { // Check stop flag in outer loop too
        struct data_path *pos_data_path, *n_data_path;

        list_for_each_entry_safe(pos_data_path, n_data_path, &data_path_list, list) {
            if (pos_data_path->depth < i) { // Process only current depth level
                continue;
            }
            struct my_dir_context ctx = { .ctx.actor = my_actor,
                              .data_path_list = &data_path_list,
                              .parent_dir = pos_data_path->dirpath,
                              .private_data = uid_data,
                              .depth = pos_data_path->depth, // Use current item's depth for recursion
                              .stop = &stop,
                              .root_sb = root_sb };
            struct file *file;

            if (!stop) {
                file = ksu_filp_open_compat(pos_data_path->dirpath, O_RDONLY | O_NOFOLLOW | O_DIRECTORY, 0);
                if (IS_ERR(file)) {
                    pr_err("Failed to open directory: %s, err: %ld\n", pos_data_path->dirpath, PTR_ERR(file));
                    // list_del(&pos_data_path->list); // remove before kfree
                    // kfree(pos_data_path);
                    // continue; // Skip this entry
                    goto skip_iterate_and_free;
                }

                iterate_dir(file, &ctx.ctx);
                filp_close(file, NULL);
            }
skip_iterate_and_free:
            list_del(&pos_data_path->list);
            kfree(pos_data_path); // Free the current item
            if (stop) break; // If manager found, break inner loop
        }
        if (stop) break; // If manager found, break outer loop
    }

    // Free any remaining items in data_path_list if search was stopped early or loop finished
    struct data_path *pos_data_path_cleanup, *n_data_path_cleanup;
    list_for_each_entry_safe(pos_data_path_cleanup, n_data_path_cleanup, &data_path_list, list) {
        list_del(&pos_data_path_cleanup->list);
        kfree(pos_data_path_cleanup);
    }

    // clear apk_path_hash_list unconditionally
    pr_info("search manager: cleanup apk_path_hash_list!\n");
    struct apk_path_hash *pos_apk_hash_cleanup, *n_apk_hash_cleanup;
    list_for_each_entry_safe(pos_apk_hash_cleanup, n_apk_hash_cleanup, &apk_path_hash_list, list) {
        list_del(&pos_apk_hash_cleanup->list);
        kfree(pos_apk_hash_cleanup);
    }
}

static bool is_uid_exist(uid_t uid, char *package, void *data)
{
    struct list_head *list = (struct list_head *)data;
    struct uid_data *np;

    bool exist = false;
    list_for_each_entry (np, list, list) {
        if (np->uid == uid % 100000 &&
            strncmp(np->package, package, KSU_MAX_PACKAGE_NAME) == 0) {
            exist = true;
            break;
        }
    }
    return exist;
}

void track_throne()
{
    struct file *fp =
        ksu_filp_open_compat(SYSTEM_PACKAGES_LIST_PATH, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        pr_err("%s: open " SYSTEM_PACKAGES_LIST_PATH " failed: %ld\n",
               __func__, PTR_ERR(fp));
        return;
    }

    struct list_head uid_list;
    INIT_LIST_HEAD(&uid_list);

    char chr = 0;
    loff_t pos = 0;
    loff_t line_start = 0;
    // Increased buffer size to handle potential long lines in packages.list
    char buf[KSU_MAX_PACKAGE_NAME + 64]; // Enough for package_name + uid + spaces + null terminator
    for (;;) {
        ssize_t count =
            ksu_kernel_read_compat(fp, &chr, sizeof(chr), &pos);
        if (count != sizeof(chr)) // End of file or read error
            break;
        if (chr != '\n')
            continue;

        // Read the whole line from line_start up to (but not including) the current newline (pos-1)
        loff_t current_line_length = (pos - 1) - line_start;
        if (current_line_length <= 0 || current_line_length >= sizeof(buf)) {
            pr_warn("Invalid line length %lld or too long in packages.list, skipping.\n", current_line_length);
            line_start = pos; // Move to start of next line
            continue;
        }
        
        // ksu_kernel_read_compat modifies its pos argument, so use a temp one for reading the line
        loff_t temp_line_read_pos = line_start;
        count = ksu_kernel_read_compat(fp, buf, current_line_length, &temp_line_read_pos);
        
        if (count != current_line_length) {
            pr_err("Failed to read full line from packages.list, read %zd, expected %lld\n", count, current_line_length);
            // Decide if to break or try to recover
            break; 
        }
        buf[count] = '\0'; // Null-terminate the read line

        struct uid_data *data =
            kzalloc(sizeof(struct uid_data), GFP_KERNEL); // Use GFP_KERNEL if not in atomic context
        if (!data) {
            pr_err("kzalloc failed for uid_data\n");
            // filp_close(fp, 0); // Already closed before goto out
            goto out; // Free already allocated list items
        }

        char *tmp = buf;
        const char *delim = " ";
        char *package = strsep(&tmp, delim);
        char *uid_str = strsep(&tmp, delim); // Renamed from uid to avoid conflict
        // Potentially more fields after uid, like version code, flags etc. We only care about package and uid.

        if (!uid_str || !package) {
            pr_err("update_uid: package or uid_str is NULL! Line: '%s'\n", buf);
            kfree(data);
            line_start = pos; // Move to start of next line
            continue;
        }

        u32 res;
        if (kstrtou32(uid_str, 10, &res)) {
            pr_err("update_uid: uid parse err for '%s' in line: '%s'\n", uid_str, buf);
            kfree(data);
            line_start = pos; // Move to start of next line
            continue;
        }
        data->uid = res;
        strscpy(data->package, package, KSU_MAX_PACKAGE_NAME);
        list_add_tail(&data->list, &uid_list);
        // reset line start for the next line
        line_start = pos;
    }
    filp_close(fp, 0);

    // now update uid list
    struct uid_data *np_uid; // Renamed to avoid conflict
    struct uid_data *n_uid;  // Renamed to avoid conflict

    // first, check if manager_uid exist!
    bool manager_exist = false;
    if (ksu_is_manager_uid_valid()) { // Only check if a manager UID is already set
        list_for_each_entry (np_uid, &uid_list, list) {
            // if manager is installed in work profile, the uid in packages.list is still equals main profile
            // don't delete it in this case!
            int manager_uid_val = ksu_get_manager_uid() % 100000; // Compare with app UID part
            if (np_uid->uid == manager_uid_val) {
                // Further check if package name matches the manager's package name if known
                // This requires getting the manager's package name, which is not directly stored with ksu_manager_uid
                // For now, UID match is considered sufficient for "manager_exist"
                manager_exist = true;
                pr_info("Current manager UID %d found in packages.list for package %s.\n", manager_uid_val, np_uid->package);
                break;
            }
        }
    }


    if (!manager_exist) {
        if (ksu_is_manager_uid_valid()) {
            pr_info("Previously set manager (UID %d) is no longer in packages.list or its UID changed, invalidating it!\n", ksu_get_manager_uid());
            ksu_invalidate_manager_uid();
            // Proceed to search for a new manager
        }
        pr_info("Searching manager...\n");
        search_manager("/data/app", 2, &uid_list); // Search depth 2: /data/app -> /data/app/pkg-dir -> /data/app/pkg-dir/base.apk
        pr_info("Search manager finished. Current manager UID: %d\n", ksu_get_manager_uid());
    }

// prune: // Label not strictly needed if logic flows directly
    // then prune the allowlist
    ksu_prune_allowlist(is_uid_exist, &uid_list);
out:
    // free uid_list
    list_for_each_entry_safe (np_uid, n_uid, &uid_list, list) {
        list_del(&np_uid->list);
        kfree(np_uid);
    }
}

void ksu_throne_tracker_init()
{
    // nothing to do
}

void ksu_throne_tracker_exit()
{
    // nothing to do
}