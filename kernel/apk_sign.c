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

static bool check_block(struct file *fp, u32 *size4_buf, loff_t *pos, u32 *offset)
{
    loff_t original_pos = *pos;
    u32 initial_offset = *offset; // Save initial offset to calculate total consumed by this function

    ksu_kernel_read_compat(fp, size4_buf, 0x4, pos); // signer length
    // *offset += 4; // This offset is relative to the start of the ID-value pair's value
    ksu_kernel_read_compat(fp, size4_buf, 0x4, pos); // signed data length
    // *offset += 4;
    ksu_kernel_read_compat(fp, size4_buf, 0x4, pos); // digests-sequence length
    // *offset += 4;
    
    u32 digests_len = *size4_buf;
    *pos += digests_len; // Skip digests body
    // *offset += digests_len;

    ksu_kernel_read_compat(fp, size4_buf, 0x4, pos); // certificates-sequence length
    // *offset += 4;
    u32 certs_sequence_len = *size4_buf;
    loff_t certs_sequence_end_pos = *pos + certs_sequence_len;
    bool found_matching_key = false;

    while (*pos < certs_sequence_end_pos && !found_matching_key) {
        u32 current_cert_len;
        ksu_kernel_read_compat(fp, &current_cert_len, 0x4, pos);
        // *offset += 4;

        if (current_cert_len == 0 || current_cert_len > CERT_MAX_LENGTH) {
            pr_info("Invalid or too long certificate in v2 block: len %u\n", current_cert_len);
            *pos = certs_sequence_end_pos; // Skip rest of certs sequence
            break;
        }

        char cert_data_buf[CERT_MAX_LENGTH]; // Re-declare to ensure it's on stack if CERT_MAX_LENGTH is large
        if (current_cert_len > sizeof(cert_data_buf)) { // Should not happen due to CERT_MAX_LENGTH check
            pr_err("V2 cert len %u exceeds buffer %zu\n", current_cert_len, sizeof(cert_data_buf));
            *pos += current_cert_len; // Skip this cert's data
            // *offset += current_cert_len;
            continue;
        }

        ksu_kernel_read_compat(fp, cert_data_buf, current_cert_len, pos); // Read cert data, *pos advances
        // *offset += current_cert_len;

        for (int i = 0; i < ARRAY_SIZE(apk_sign_keys); i++) {
            if (current_cert_len == apk_sign_keys[i].size) {
                unsigned char digest[SHA256_DIGEST_SIZE];
                if (IS_ERR(ksu_sha256(cert_data_buf, current_cert_len, digest))) {
                    pr_info("v2 sha256 error for cert\n");
                    continue;
                }
                char hash_str[SHA256_DIGEST_SIZE * 2 + 1];
                bin2hex(hash_str, digest, SHA256_DIGEST_SIZE);
                hash_str[SHA256_DIGEST_SIZE * 2] = '\0';
                if (strcmp(apk_sign_keys[i].sha256, hash_str) == 0) {
                    pr_info("v2 signature match: key %d, hash %s\n", i, hash_str);
                    found_matching_key = true;
                    break; 
                }
            }
        }
    }

    *pos = certs_sequence_end_pos; // Ensure pos is at the end of certificates sequence
    *offset = initial_offset + (*pos - original_pos); // Update offset with total bytes consumed by this function

    return found_matching_key;
}

// New function for v3 APK Signers
static bool check_v3_apk_signer(struct file *fp, u32 *size4_buf, loff_t *pos, u32 *offset) {
    loff_t original_pos_in_signer = *pos;
    u32 initial_offset_val = *offset; // Save initial offset

    // A v3 block's value is a sequence of length-prefixed signers.
    // This function is called for one such ID-value pair (the v3 block).
    // We will parse the first signer in this v3 block.
    // A more complete impl would loop through all signers in the v3 block.

    // Read signer length (this is the length of the first signer in the sequence)
    // ksu_kernel_read_compat(fp, size4_buf, 0x4, pos); 
    // u32 signer_total_len = *size4_buf;
    // loff_t signer_end_pos = *pos + signer_total_len;
    // For simplicity, we'll parse fields sequentially and assume one primary signer.

    // Read signed_data_len for the first signer
    ksu_kernel_read_compat(fp, size4_buf, 0x4, pos);
    u32 signed_data_len = *size4_buf;
    loff_t signed_data_start_pos = *pos;
    loff_t signed_data_end_pos = *pos + signed_data_len;

    // Inside signed_data:
    // 1. digests sequence (length-prefixed)
    ksu_kernel_read_compat(fp, size4_buf, 0x4, pos);
    u32 digests_sequence_len = *size4_buf;
    *pos += digests_sequence_len; // Skip digests

    // 2. certificates sequence (length-prefixed)
    ksu_kernel_read_compat(fp, size4_buf, 0x4, pos);
    u32 certs_sequence_len = *size4_buf;
    loff_t certs_sequence_end_pos = *pos + certs_sequence_len;
    bool found_matching_key = false;

    while (*pos < certs_sequence_end_pos && !found_matching_key) {
        u32 current_cert_len;
        ksu_kernel_read_compat(fp, &current_cert_len, 0x4, pos);

        if (current_cert_len == 0 || current_cert_len > CERT_MAX_LENGTH) {
            pr_info("Invalid or too long certificate in v3 block: len %u\n", current_cert_len);
            *pos = certs_sequence_end_pos; // Skip rest of certs sequence
            break;
        }
        
        char cert_data_buf[CERT_MAX_LENGTH];
        if (current_cert_len > sizeof(cert_data_buf)) {
            pr_err("V3 cert len %u exceeds buffer %zu\n", current_cert_len, sizeof(cert_data_buf));
            *pos += current_cert_len;
            continue;
        }

        ksu_kernel_read_compat(fp, cert_data_buf, current_cert_len, pos);

        for (int i = 0; i < ARRAY_SIZE(apk_sign_keys); i++) {
            if (current_cert_len == apk_sign_keys[i].size) {
                unsigned char digest[SHA256_DIGEST_SIZE];
                if (IS_ERR(ksu_sha256(cert_data_buf, current_cert_len, digest))) {
                    pr_info("v3 sha256 error for cert\n");
                    continue;
                }
                char hash_str[SHA256_DIGEST_SIZE * 2 + 1];
                bin2hex(hash_str, digest, SHA256_DIGEST_SIZE);
                hash_str[SHA256_DIGEST_SIZE * 2] = '\0';
                if (strcmp(apk_sign_keys[i].sha256, hash_str) == 0) {
                    pr_info("v3 signature match: key %d, hash %s\n", i, hash_str);
                    found_matching_key = true;
                    break;
                }
            }
        }
    }
    
    *pos = certs_sequence_end_pos; // Ensure pos is at end of certs sequence

    // Skip rest of signed_data (minSdk, maxSdk, additional_attributes)
    *pos = signed_data_end_pos;

    // For this simplified version, we assume that if a cert matches, the v3 signer is good enough.
    // A full v3 verifier would parse signatures, public_key, proof-of-rotation etc.
    // We need to ensure *pos is advanced to the end of this *one* signer we parsed,
    // or rely on the caller to skip the rest of the v3 ID-value pair.
    // The current logic updates *pos up to the end of signed_data.
    // The caller uses `offset` to skip the rest of the ID-value pair.
    // So, update `offset` with bytes consumed from `original_pos_in_signer`.
    
    // To correctly skip the rest of this specific signer (if there were multiple in the v3 block)
    // and then the rest of the v3 block, we'd need the signer_total_len.
    // For now, we've parsed one signer's certs.
    // The caller's `pos_val_start + (size8_val_len - current_offset_in_val)` will skip the rest of the v3 block.
    // So, `*offset` should reflect bytes consumed from the start of the v3 block's value.
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

static __always_inline bool is_apk_signature_valid(char *path)
{
    unsigned char buffer[0x11] = { 0 };
    u32 size4; // Used as a temporary buffer for reading u32 values
    u64 size8_val_len; // Length of the current ID-value pair's value
    u64 size_of_apk_sig_block; // Total size of the APK Signing Block

    loff_t pos;
    loff_t eocd_pos; // Position of the EOCD record
    loff_t apk_sig_block_start_pos;

    bool v2_signature_ok = false;
    int v2_sig_blocks_found = 0;
    bool v3_signature_ok = false;
    int v3_sig_blocks_found = 0; // For 0xf05368c0 or 0x1b93ad61

    int i;
    struct file *fp = ksu_filp_open_compat(path, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        pr_err("open %s error: %ld.\n", path, PTR_ERR(fp));
        return false;
    }

    fp->f_mode |= FMODE_NONOTIFY;

    for (i = 0;; ++i) {
        unsigned short comment_len_check;
        // Seek from end to find EOCD comment length field
        eocd_pos = generic_file_llseek(fp, -i - 2, SEEK_END);
        if (eocd_pos < 0) { // File too small or seek error
            pr_info("error: file too small or seek error finding EOCD\n");
            goto clean_exit;
        }
        if (ksu_kernel_read_compat(fp, &comment_len_check, 2, &eocd_pos) != 2) {
            pr_info("error: reading EOCD comment length\n");
            goto clean_exit;
        }

        if (comment_len_check == i) { // Found EOCD
            // EOCD signature is 22 bytes before comment_len_check field
            eocd_pos = generic_file_llseek(fp, -i - 22, SEEK_END);
            if (ksu_kernel_read_compat(fp, &size4, 4, &eocd_pos) != 4) { // Read EOCD signature
                pr_info("error: reading EOCD signature\n");
                goto clean_exit;
            }
            if (size4 == 0x06054b50) { // PK\x05\x06
                break; // EOCD found
            }
        }
        if (i == 0xffff) {
            pr_info("error: cannot find EOCD record\n");
            goto clean_exit;
        }
    }

    // EOCD found, eocd_pos is at the start of EOCD signature.
    // Offset of central directory is 16 bytes from start of EOCD signature.
    pos = eocd_pos + 16;

#ifdef CONFIG_KSU_DEBUG
    struct inode *inode = file_inode(fp);
    loff_t file_size = inode ? i_size_read(inode) : -1L;
    pr_info("KSU_SIGN: EOCD at %lld, file_size %lld. Reading CD offset from %lld for %s\n", eocd_pos, file_size, pos, path);
#endif

    ssize_t bytes_read_ret;
    bytes_read_ret = ksu_kernel_read_compat(fp, &size4, 0x4, &pos);
    if (bytes_read_ret != 4) { // Read offset of central directory
#ifdef CONFIG_KSU_DEBUG
        pr_err("KSU_SIGN: Failed to read CD offset for %s. Read returned %zd, expected 4. EOCD_pos: %lld, read_pos_attempt: %lld\n", path, bytes_read_ret, eocd_pos, (eocd_pos + 16));
#endif
        pr_err("error: reading central directory offset\n"); // This is the original error
        goto clean_exit;
    }
    // This size4 is the offset of the start of the central directory.
    // The APK Signing Block is located immediately before the Central Directory.
    // Its last 16 bytes are "APK Sig Block 42" magic and size of block.
    apk_sig_block_start_pos = size4 - 0x18; // Tentative: 24 bytes = 8 (size) + 16 (magic)
    if (apk_sig_block_start_pos < 0) {
        pr_info("error: invalid central directory offset for APK sig block\n");
        goto clean_exit;
    }
    pos = apk_sig_block_start_pos;

    if (ksu_kernel_read_compat(fp, &size_of_apk_sig_block, 0x8, &pos) != 8) { // Read size of APK Signing Block
        pr_info("error: reading size of APK sig block\n");
        goto clean_exit;
    }
    if (ksu_kernel_read_compat(fp, buffer, 0x10, &pos) != 0x10) { // Read magic "APK Sig Block 42"
        pr_info("error: reading APK sig block magic\n");
        goto clean_exit;
    }
    if (memcmp((char *)buffer, "APK Sig Block 42", 16) != 0) {
        pr_info("error: APK Sig Block 42 magic not found\n");
        goto clean_exit;
    }

    // Position 'pos' is now at the end of the APK Signing Block footer (after magic).
    // The actual ID-value pairs start earlier.
    // Start of ID-value pairs is at apk_sig_block_start_pos - size_of_apk_sig_block + 8 (size of footer's size field)
    // No, it's: CD_offset - size_of_apk_sig_block - 8 (for the size field before the pairs)
    pos = size4 - size_of_apk_sig_block - 8; // Start of the first ID-value pair's size field
    
    loff_t current_block_values_end_pos = size4 - 8; // End of all ID-value pairs (before overall block size)

    int loop_count = 0;
    while (pos < current_block_values_end_pos && loop_count++ < 10) { // Loop through ID-value pairs
        u32 id;
        u32 current_offset_in_val; // Tracks bytes consumed from start of current ID-value's value
        loff_t pos_val_start;     // To help advance pos after processing a block

        if (ksu_kernel_read_compat(fp, &size8_val_len, 0x8, &pos) != 8) break; // Length of this ID-value pair's value
        if (size8_val_len == 0 || size8_val_len > size_of_apk_sig_block) { // Sanity check
            pr_info("Invalid ID-value pair size: %llu\n", size8_val_len);
            break;
        }
        
        pos_val_start = pos; // Mark start of ID + value data for this pair
        
        if (ksu_kernel_read_compat(fp, &id, 0x4, &pos) != 4) break; // ID
        current_offset_in_val = 4; // Consumed ID

        if (id == 0x7109871au) { // APK Signature Scheme v2 ID
            v2_sig_blocks_found++;
            if (check_block(fp, &size4, &pos, &current_offset_in_val)) {
                v2_signature_ok = true;
            }
        } else if (id == 0xf05368c0u || id == 0x1b93ad61u) { // v3 or v3.1 ID
            v3_sig_blocks_found++;
            // For v3/v3.1, the value is a sequence of signers. check_v3_apk_signer parses the first.
            if (check_v3_apk_signer(fp, &size4, &pos, &current_offset_in_val)) {
                v3_signature_ok = true;
            }
        } else {
#ifdef CONFIG_KSU_DEBUG
            pr_info("Unknown signature scheme ID: 0x%08x, len: %llu\n", id, size8_val_len);
#endif
            // Skip unknown block
        }
        // Advance pos to the start of the next ID-value pair's size
        // pos should have been updated by check_block/check_v3_apk_signer
        // current_offset_in_val should reflect total bytes read for this ID-value (ID + processed value part)
        // We need to skip (size8_val_len - (current_offset_in_val - 4)) bytes from current pos
        // Or, more simply:
        pos = pos_val_start + size8_val_len; // Go to end of current ID-value pair's value
    }

    bool final_signature_valid = false;
    if (v2_signature_ok) {
        if (v2_sig_blocks_found == 1) {
            final_signature_valid = true;
            pr_info("APK V2 signature verified.\n");
        } else {
            pr_err("V2 signature valid but unexpected block count: %d\n", v2_sig_blocks_found);
        }
    }
    
    if (!final_signature_valid && v3_signature_ok) { // Prefer v2 if both somehow pass, or allow if only v3 passes
        if (v3_sig_blocks_found >= 1) { // v3 might have multiple signers in one block, or multiple v3 blocks (unlikely)
            final_signature_valid = true;
            pr_info("APK V3 signature verified.\n");
        } else {
            pr_err("V3 signature valid but unexpected block count: %d\n", v3_sig_blocks_found);
        }
    }


    if (final_signature_valid) {
        // Reset file position for has_v1_signature_file
        generic_file_llseek(fp, 0, SEEK_SET);
        if (has_v1_signature_file(fp)) {
            pr_err("Valid v2/v3 signature found, but also unexpected v1 signature scheme!\n");
            final_signature_valid = false;
        }
    }

clean_exit:
    filp_close(fp, 0);
    return final_signature_valid;
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
