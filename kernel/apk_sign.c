#include <linux/err.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/version.h>
#ifdef CONFIG_KSU_DEBUG
#include <linux/moduleparam.h>
#endif
#include <crypto/hash.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#include <crypto/sha2.h>
#else
#include <crypto/sha.h>
#endif

#include "apk_sign.h"
#include "klog.h" // IWYU pragma: keep
#include "kernel_compat.h"
#include "manager_sign.h"

struct sdesc {
	struct shash_desc shash;
	char ctx[];
};

static struct apk_sign_key {
	unsigned size;
	const char *sha256;
} apk_sign_keys[] = {
	{EXPECTED_SIZE, EXPECTED_HASH}, // Official
	{EXPECTED_SIZE_RSUNTK, EXPECTED_HASH_RSUNTK}, // RKSU
	{EXPECTED_SIZE_5EC1CFF, EXPECTED_HASH_5EC1CFF}, // MKSU
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
	struct sdesc *sdesc;
	int size;

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kmalloc(size, GFP_KERNEL);
	if (!sdesc)
		return ERR_PTR(-ENOMEM);
	sdesc->shash.tfm = alg;
	return sdesc;
}

static int calc_hash(struct crypto_shash *alg, const unsigned char *data,
		     unsigned int datalen, unsigned char *digest)
{
	struct sdesc *sdesc;
	int ret;

	sdesc = init_sdesc(alg);
	if (IS_ERR(sdesc)) {
		pr_info("can't alloc sdesc\n");
		return PTR_ERR(sdesc);
	}

	ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
	kfree(sdesc);
	return ret;
}

static int ksu_sha256(const unsigned char *data, unsigned int datalen,
		      unsigned char *digest)
{
	struct crypto_shash *alg;
	char *hash_alg_name = "sha256";
	int ret;

	alg = crypto_alloc_shash(hash_alg_name, 0, 0);
	if (IS_ERR(alg)) {
		pr_info("can't alloc alg %s\n", hash_alg_name);
		return PTR_ERR(alg);
	}
	ret = calc_hash(alg, data, datalen, digest);
	crypto_free_shash(alg);
	return ret;
}

static bool check_block(struct file *fp, u32 *size4_buf, loff_t *pos, u32 *offset,
            const struct ksu_cert_check_params *target_key)
{
    loff_t original_pos = *pos;
    u32 initial_offset = *offset;

    ksu_kernel_read_compat(fp, size4_buf, 0x4, pos); // signer length
    ksu_kernel_read_compat(fp, size4_buf, 0x4, pos); // signed data length
    ksu_kernel_read_compat(fp, size4_buf, 0x4, pos); // digests-sequence length
    
    u32 digests_len = *size4_buf;
    *pos += digests_len; // Skip digests body

    ksu_kernel_read_compat(fp, size4_buf, 0x4, pos); // certificates-sequence length
    u32 certs_sequence_len = *size4_buf;
    loff_t certs_sequence_end_pos = *pos + certs_sequence_len;
    bool found_matching_key = false;

    while (*pos < certs_sequence_end_pos && !found_matching_key) {
        u32 current_cert_len;
        ksu_kernel_read_compat(fp, &current_cert_len, 0x4, pos);

        if (current_cert_len == 0 || current_cert_len > CERT_MAX_LENGTH) {
            pr_info("Invalid or too long certificate in v2 block: len %u\n", current_cert_len);
            *pos = certs_sequence_end_pos; 
            break;
        }

        char cert_data_buf[CERT_MAX_LENGTH]; 
        if (current_cert_len > sizeof(cert_data_buf)) { 
            pr_err("V2 cert len %u exceeds buffer %zu\n", current_cert_len, sizeof(cert_data_buf));
            *pos += current_cert_len; 
            continue;
        }

        ksu_kernel_read_compat(fp, cert_data_buf, current_cert_len, pos);

        unsigned char digest[SHA256_DIGEST_SIZE];
        if (IS_ERR(ksu_sha256(cert_data_buf, current_cert_len, digest))) {
            pr_info("v2 sha256 error for cert\n");
            continue;
        }
        char hash_str[SHA256_DIGEST_SIZE * 2 + 1];
        bin2hex(hash_str, digest, SHA256_DIGEST_SIZE);
        hash_str[SHA256_DIGEST_SIZE * 2] = '\0';

        if (target_key) { // Check against a specific key if provided
            if (current_cert_len == target_key->size &&
                strcmp(target_key->sha256, hash_str) == 0) {
                pr_info("v2 signature match (specific key): hash %s\n", hash_str);
                found_matching_key = true;
            }
        } else { // Fallback to global apk_sign_keys
            for (int i = 0; i < ARRAY_SIZE(apk_sign_keys); i++) {
                if (current_cert_len == apk_sign_keys[i].size &&
                    strcmp(apk_sign_keys[i].sha256, hash_str) == 0) {
                    pr_info("v2 signature match (global key %d): hash %s\n", i, hash_str);
                    found_matching_key = true;
                    break; 
                }
            }
        }
    }

    *pos = certs_sequence_end_pos;
    *offset = initial_offset + (*pos - original_pos);

    return found_matching_key;
}

static bool check_v3_apk_signer(struct file *fp, u32 *size4_buf, loff_t *pos, u32 *offset,
                const struct ksu_cert_check_params *target_key) {
    loff_t original_pos_in_signer = *pos;
    u32 initial_offset_val = *offset;

    ksu_kernel_read_compat(fp, size4_buf, 0x4, pos); // signed_data_len
    u32 signed_data_len = *size4_buf;
    // loff_t signed_data_start_pos = *pos; // Not used
    loff_t signed_data_end_pos = *pos + signed_data_len;

    ksu_kernel_read_compat(fp, size4_buf, 0x4, pos); // digests sequence length
    u32 digests_sequence_len = *size4_buf;
    *pos += digests_sequence_len; // Skip digests

    ksu_kernel_read_compat(fp, size4_buf, 0x4, pos); // certificates sequence length
    u32 certs_sequence_len = *size4_buf;
    loff_t certs_sequence_end_pos = *pos + certs_sequence_len;
    bool found_matching_key = false;

    while (*pos < certs_sequence_end_pos && !found_matching_key) {
        u32 current_cert_len;
        ksu_kernel_read_compat(fp, &current_cert_len, 0x4, pos);

        if (current_cert_len == 0 || current_cert_len > CERT_MAX_LENGTH) {
            pr_info("Invalid or too long certificate in v3 block: len %u\n", current_cert_len);
            *pos = certs_sequence_end_pos;
            break;
        }
        
        char cert_data_buf[CERT_MAX_LENGTH];
        if (current_cert_len > sizeof(cert_data_buf)) {
            pr_err("V3 cert len %u exceeds buffer %zu\n", current_cert_len, sizeof(cert_data_buf));
            *pos += current_cert_len;
            continue;
        }

        ksu_kernel_read_compat(fp, cert_data_buf, current_cert_len, pos);

        unsigned char digest_buf[SHA256_DIGEST_SIZE]; // Renamed from 'digest' to avoid conflict
        if (IS_ERR(ksu_sha256(cert_data_buf, current_cert_len, digest_buf))) {
            pr_info("v3 sha256 error for cert\n");
            continue;
        }
        char hash_str[SHA256_DIGEST_SIZE * 2 + 1];
        bin2hex(hash_str, digest_buf, SHA256_DIGEST_SIZE);
        hash_str[SHA256_DIGEST_SIZE * 2] = '\0';

        if (target_key) { // Check against a specific key if provided
            if (current_cert_len == target_key->size &&
                strcmp(target_key->sha256, hash_str) == 0) {
                pr_info("v3 signature match (specific key): hash %s\n", hash_str);
                found_matching_key = true;
            }
        } else { // Fallback to global apk_sign_keys
            for (int i = 0; i < ARRAY_SIZE(apk_sign_keys); i++) {
                if (current_cert_len == apk_sign_keys[i].size &&
                    strcmp(apk_sign_keys[i].sha256, hash_str) == 0) {
                    pr_info("v3 signature match (global key %d): hash %s\n", i, hash_str);
                    found_matching_key = true;
                    break;
                }
            }
        }
    }
    
    *pos = certs_sequence_end_pos; 
    *pos = signed_data_end_pos; // Skip rest of signed_data

    *offset = initial_offset_val + (*pos - original_pos_in_signer);

    return found_matching_key;
}

struct zip_entry_header {
	uint32_t signature;
	uint16_t version;
	uint16_t flags;
	uint16_t compression;
	uint16_t mod_time;
	uint16_t mod_date;
	uint32_t crc32;
	uint32_t compressed_size;
	uint32_t uncompressed_size;
	uint16_t file_name_length;
	uint16_t extra_field_length;
} __attribute__((packed));

// This is a necessary but not sufficient condition, but it is enough for us
static bool has_v1_signature_file(struct file *fp)
{
	struct zip_entry_header header;
	const char MANIFEST[] = "META-INF/MANIFEST.MF";

	loff_t pos = 0;

	while (ksu_kernel_read_compat(fp, &header,
				      sizeof(struct zip_entry_header), &pos) ==
	       sizeof(struct zip_entry_header)) {
		if (header.signature != 0x04034b50) {
			// ZIP magic: 'PK'
			return false;
		}
		// Read the entry file name
		if (header.file_name_length == sizeof(MANIFEST) - 1) {
			char fileName[sizeof(MANIFEST)];
			ksu_kernel_read_compat(fp, fileName,
					       header.file_name_length, &pos);
			fileName[header.file_name_length] = '\0';

			// Check if the entry matches META-INF/MANIFEST.MF
			if (strncmp(MANIFEST, fileName, sizeof(MANIFEST) - 1) ==
			    0) {
				return true;
			}
		} else {
			// Skip the entry file name
			pos += header.file_name_length;
		}

		// Skip to the next entry
		pos += header.extra_field_length + header.compressed_size;
	}

	return false;
}

static __always_inline bool __is_apk_signature_valid_common(const char *path, const struct ksu_cert_check_params *target_key)
{
    unsigned char buffer[0x11] = { 0 };
    u32 size4; 
    u64 size8_val_len; 
    u64 size_of_apk_sig_block;

    loff_t pos;
    loff_t eocd_pos; 
    loff_t apk_sig_block_start_pos;

    bool v2_signature_ok = false;
    int v2_sig_blocks_found = 0;
    bool v3_signature_ok = false;
    int v3_sig_blocks_found = 0;

    int i;
    struct file *fp = ksu_filp_open_compat(path, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        pr_err("open %s error: %ld.\n", path, PTR_ERR(fp));
        return false;
    }

    fp->f_mode |= FMODE_NONOTIFY;

    for (i = 0;; ++i) {
        unsigned short comment_len_check;
        eocd_pos = generic_file_llseek(fp, -i - 2, SEEK_END);
        if (eocd_pos < 0) {
            pr_info("error: file too small or seek error finding EOCD for %s\n", path);
            goto clean_exit_common;
        }
        if (ksu_kernel_read_compat(fp, &comment_len_check, 2, &eocd_pos) != 2) {
            pr_info("error: reading EOCD comment length for %s\n", path);
            goto clean_exit_common;
        }

        if (comment_len_check == i) { 
            eocd_pos = generic_file_llseek(fp, -i - 22, SEEK_END);
            if (ksu_kernel_read_compat(fp, &size4, 4, &eocd_pos) != 4) { 
                pr_info("error: reading EOCD signature for %s\n", path);
                goto clean_exit_common;
            }
            if (size4 == 0x06054b50) { // PK\x05\x06
#ifdef CONFIG_KSU_DEBUG
                struct inode *inode_dbg = file_inode(fp);
                loff_t file_size_dbg = inode_dbg ? i_size_read(inode_dbg) : -1L;
                pr_info("KSU_SIGN: EOCD signature 0x%08x found at eocd_pos %lld. Iteration i=%d. File size: %lld. Path: %s\n", size4, eocd_pos, i, file_size_dbg, path);
#endif
                break; 
            }
        }
        if (i == 0xffff) {
            pr_info("error: cannot find EOCD record for %s\n", path);
            goto clean_exit_common;
        }
    }

    pos = eocd_pos + 16;

#ifdef CONFIG_KSU_DEBUG
    struct inode *inode = file_inode(fp);
    loff_t file_size = inode ? i_size_read(inode) : -1L;
    pr_info("KSU_SIGN: EOCD at %lld, file_size %lld. Reading CD offset from %lld for %s\n", eocd_pos, file_size, pos, path);
#endif

    ssize_t bytes_read_ret;
    bytes_read_ret = ksu_kernel_read_compat(fp, &size4, 0x4, &pos);
    if (bytes_read_ret != 4) { 
#ifdef CONFIG_KSU_DEBUG
        pr_err("KSU_SIGN: Failed to read CD offset for %s. Read returned %zd, expected 4. EOCD_pos: %lld, read_pos_attempt: %lld\n", path, bytes_read_ret, eocd_pos, (eocd_pos + 16));
#endif
        pr_err("error: reading central directory offset for %s\n", path);
        goto clean_exit_common;
    }
    
    apk_sig_block_start_pos = size4 - 0x18; 
    if (apk_sig_block_start_pos < 0) {
        pr_info("error: invalid central directory offset for APK sig block in %s\n", path);
        goto clean_exit_common;
    }
    pos = apk_sig_block_start_pos;

    if (ksu_kernel_read_compat(fp, &size_of_apk_sig_block, 0x8, &pos) != 8) { 
        pr_info("error: reading size of APK sig block for %s\n", path);
        goto clean_exit_common;
    }
    if (ksu_kernel_read_compat(fp, buffer, 0x10, &pos) != 0x10) { 
        pr_info("error: reading APK sig block magic for %s\n", path);
        goto clean_exit_common;
    }
    if (memcmp((char *)buffer, "APK Sig Block 42", 16) != 0) {
        pr_info("error: APK Sig Block 42 magic not found in %s\n", path);
        goto clean_exit_common;
    }

    pos = size4 - size_of_apk_sig_block - 8; 
    loff_t current_block_values_end_pos = size4 - 8;

    int loop_count = 0;
    while (pos < current_block_values_end_pos && loop_count++ < 10) { 
        u32 id;
        u32 current_offset_in_val = 0; // Initialize
        loff_t pos_val_start;     

        if (ksu_kernel_read_compat(fp, &size8_val_len, 0x8, &pos) != 8) break; 
        if (size8_val_len == 0 || size8_val_len > size_of_apk_sig_block) { 
            pr_info("Invalid ID-value pair size: %llu in %s\n", size8_val_len, path);
            break;
        }
        
        pos_val_start = pos; 
        
        if (ksu_kernel_read_compat(fp, &id, 0x4, &pos) != 4) break; 
        current_offset_in_val = 4; 

        if (id == 0x7109871au) { 
            v2_sig_blocks_found++;
            if (check_block(fp, &size4, &pos, &current_offset_in_val, target_key)) {
                v2_signature_ok = true;
            }
        } else if (id == 0xf05368c0u || id == 0x1b93ad61u) { 
            v3_sig_blocks_found++;
            if (check_v3_apk_signer(fp, &size4, &pos, &current_offset_in_val, target_key)) {
                v3_signature_ok = true;
            }
        } else {
#ifdef CONFIG_KSU_DEBUG
            pr_info("Unknown signature scheme ID: 0x%08x, len: %llu in %s\n", id, size8_val_len, path);
#endif
        }
        pos = pos_val_start + size8_val_len; 
    }

    bool final_signature_valid = false;
    if (v2_signature_ok) {
        if (v2_sig_blocks_found == 1) {
            final_signature_valid = true;
            pr_info("APK V2 signature verified for %s.\n", path);
        } else {
            pr_err("V2 signature valid but unexpected block count: %d for %s\n", v2_sig_blocks_found, path);
        }
    }
    
    if (!final_signature_valid && v3_signature_ok) { 
        if (v3_sig_blocks_found >= 1) { 
            final_signature_valid = true;
            pr_info("APK V3 signature verified for %s.\n", path);
        } else {
            pr_err("V3 signature valid but unexpected block count: %d for %s\n", v3_sig_blocks_found, path);
        }
    }

    if (final_signature_valid) {
        generic_file_llseek(fp, 0, SEEK_SET);
        if (has_v1_signature_file(fp)) {
            pr_err("Valid v2/v3 signature found, but also unexpected v1 signature scheme in %s!\n", path);
            final_signature_valid = false;
        }
    }

clean_exit_common:
    filp_close(fp, 0);
    return final_signature_valid;
}

// New public function
bool is_apk_signed_with_key(const char *path, const char *expected_sha256, uint32_t expected_size)
{
    if (!path || !expected_sha256 || expected_size == 0) {
        pr_err("is_apk_signed_with_key: Invalid parameters (path or hash is NULL, or size is 0).\n");
        return false;
    }
    struct ksu_cert_check_params key_params = { expected_sha256, expected_size };
    return __is_apk_signature_valid_common(path, &key_params);
}

// Existing function, now calls the common internal one to use global keys
static bool is_apk_signature_valid(char *path)
{
    return __is_apk_signature_valid_common(path, NULL); // Pass NULL to use global apk_sign_keys
}

#ifdef CONFIG_KSU_DEBUG

int ksu_debug_manager_uid = -1;

#include "manager.h"

static int set_expected_size(const char *val, const struct kernel_param *kp)
{
	int rv = param_set_uint(val, kp);
	ksu_set_manager_uid(ksu_debug_manager_uid);
	pr_info("ksu_manager_uid set to %d\n", ksu_debug_manager_uid);
	return rv;
}

static struct kernel_param_ops expected_size_ops = {
	.set = set_expected_size,
	.get = param_get_uint,
};

module_param_cb(ksu_debug_manager_uid, &expected_size_ops,
		&ksu_debug_manager_uid, S_IRUSR | S_IWUSR);

#endif

bool is_manager_apk(char *path)
{
	return is_apk_signature_valid(path);
}
