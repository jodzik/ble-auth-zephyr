#include "auth.h"

#include <lib/safe-c/safe_c.h>
#include <lib/tlv-c/tlv.h>
#include <ztl/bt.h>
#include <ztl/nvs.h>

#include <zephyr/autoconf.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/timeutil.h>

#include <psa/crypto.h>

#include <string.h>
#include <stdlib.h>

#define LOCAL_BT_UUID_CHARC(charc_part_w8) ZTL_BT_UUID_CHARC(CONFIG_AUTH_BLE_SERVICE_PART_UUID, charc_part_w8)

typedef uint16_t nvs_cert_id_t;

enum {
    BT_STATUS_CHARC_UUID = 0x01,
    BT_ACTIVATE_CHARC_UUID = 0x02,
    BT_AUTH_CHARC_UUID = 0x03,
    BT_IDENTITY_KEY_CHARC_UUID = 0x04,
    BT_IDENTITY_CHALLENGE_CHARC_UUID = 0x05,
    BT_USED_CERTS_CHARC_UUID = 0x06,
    BT_REVOKE_CERT_CHARC_UUID = 0x07,
    BT_ROTATE_MASTER_KEY_CHARC_UUID = 0x08,
    BT_REMOVE_OLD_MASTER_KEY_CHARC_UUID = 0x09,
    BT_RESET_CHARC_UUID = 0x0A,
};

typedef struct AuthConn {
    struct bt_conn* conn;
    enum AuthConnStatus status;
    struct AuthLocalCert cert;
    uint8_t identity_rand[AUTH_SALT_SIZE];
    nvs_cert_id_t cert_nvs_id;
    uint16_t used_certs_ptr;
} AuthConn;

static ssize_t auth_bt_status_read_cb(
    struct bt_conn *conn,
    const struct bt_gatt_attr *attr,
	void *buf, uint16_t len,
	uint16_t offset);

static ssize_t auth_bt_activate_write_cb(
    struct bt_conn *conn,
    const struct bt_gatt_attr *attr,
    const void *buf,
    uint16_t len,
    uint16_t offset,
    uint8_t flags);

static ssize_t auth_bt_auth_write_cb(
    struct bt_conn *conn,
    const struct bt_gatt_attr *attr,
    const void *buf,
    uint16_t len,
    uint16_t offset,
    uint8_t flags);

static ssize_t auth_bt_identity_key_write_cb(
    struct bt_conn *conn,
    const struct bt_gatt_attr *attr,
    const void *buf,
    uint16_t len,
    uint16_t offset,
    uint8_t flags);

static ssize_t auth_bt_identity_challenge_read_cb(
    struct bt_conn *conn,
    const struct bt_gatt_attr *attr,
	void *buf, uint16_t len,
	uint16_t offset);

static ssize_t auth_bt_identity_challenge_write_cb(
    struct bt_conn *conn,
    const struct bt_gatt_attr *attr,
    const void *buf,
    uint16_t len,
    uint16_t offset,
    uint8_t flags);

static ssize_t auth_bt_used_certs_read_cb(
    struct bt_conn *conn,
    const struct bt_gatt_attr *attr,
	void *buf, uint16_t len,
	uint16_t offset);

static ssize_t auth_bt_used_certs_write_cb(
    struct bt_conn *conn,
    const struct bt_gatt_attr *attr,
    const void *buf,
    uint16_t len,
    uint16_t offset,
    uint8_t flags);

static ssize_t auth_bt_revoke_cert_write_cb(
    struct bt_conn *conn,
    const struct bt_gatt_attr *attr,
    const void *buf,
    uint16_t len,
    uint16_t offset,
    uint8_t flags);

static ssize_t auth_bt_rotate_master_key_write_cb(
    struct bt_conn *conn,
    const struct bt_gatt_attr *attr,
    const void *buf,
    uint16_t len,
    uint16_t offset,
    uint8_t flags);

static ssize_t auth_bt_remove_old_master_key_write_cb(
    struct bt_conn *conn,
    const struct bt_gatt_attr *attr,
    const void *buf,
    uint16_t len,
    uint16_t offset,
    uint8_t flags);

static ssize_t auth_bt_reset_write_cb(
    struct bt_conn *conn,
    const struct bt_gatt_attr *attr,
    const void *buf,
    uint16_t len,
    uint16_t offset,
    uint8_t flags);

static int auth_settings_set(char const* name, size_t len, settings_read_cb read_cb, void* cb_arg);

static void _on_bt_event(struct zbus_channel const* chan);

static char const SETTINGS_KEY_MASTER_PUB_KEY[] = "master-pub-key";
static char const SETTINGS_KEY_MASTER_PUB_KEY_FULL[] = "auth/master-pub-key";
static char const SETTINGS_KEY_MASTER_PUB_KEY_OLD[] = "master-pub-key-old";
static char const SETTINGS_KEY_MASTER_PUB_KEY_OLD_FULL[] = "auth/master-pub-key-old";
static unix_timestamp_t const CERT_LAST_USE_UPDATE_THRESHOLD = 1 * 60 * 60;

LOG_MODULE_REGISTER(auth, LOG_LEVEL_DBG);
static K_MUTEX_DEFINE(g_mutex);
static uint8_t g_master_pub_key[AUTH_PUB_KEY_SIZE] = {0};
static uint8_t g_master_pub_key_old[AUTH_PUB_KEY_SIZE] = {0};
static psa_key_id_t g_master_pub_key_id = PSA_KEY_ID_NULL;
static psa_key_id_t g_master_pub_key_old_id = PSA_KEY_ID_NULL;
static struct AuthConn g_auth_conns[CONFIG_BT_MAX_CONN] = {0};
static struct AuthLocalCertId g_local_cert_ids[CONFIG_AUTH_BLE_MAX_LOCAL_CERTS] = {0};
static struct nvs_fs g_cert_storage_nvs = {0};
static atomic_t g_auth_status = ATOMIC_INIT(AUTH_GLOBAL_STATUS__DISABLED);

ZBUS_LISTENER_DEFINE(g_auth_bt_listener, _on_bt_event);

static const struct bt_uuid_128 SERVICE_UUID = ZTL_BT_UUID_SERVICE(CONFIG_AUTH_BLE_SERVICE_PART_UUID);
static const struct bt_uuid_128 STATUS_CHARC_UUID = LOCAL_BT_UUID_CHARC(BT_STATUS_CHARC_UUID);
static const struct bt_uuid_128 ACTIVATE_CHARC_UUID = LOCAL_BT_UUID_CHARC(BT_ACTIVATE_CHARC_UUID);
static const struct bt_uuid_128 AUTH_CHARC_UUID = LOCAL_BT_UUID_CHARC(BT_AUTH_CHARC_UUID);
static const struct bt_uuid_128 IDENTITY_KEY_CHARC_UUID = LOCAL_BT_UUID_CHARC(BT_IDENTITY_KEY_CHARC_UUID);
static const struct bt_uuid_128 IDENTITY_CHALLENGE_CHARC_UUID = LOCAL_BT_UUID_CHARC(BT_IDENTITY_CHALLENGE_CHARC_UUID);
static const struct bt_uuid_128 USED_CERTS_CHARC_UUID = LOCAL_BT_UUID_CHARC(BT_USED_CERTS_CHARC_UUID);
static const struct bt_uuid_128 REVOKE_CERT_CHARC_UUID = LOCAL_BT_UUID_CHARC(BT_REVOKE_CERT_CHARC_UUID);
static const struct bt_uuid_128 ROTATE_MASTER_KEY_CHARC_UUID = LOCAL_BT_UUID_CHARC(BT_ROTATE_MASTER_KEY_CHARC_UUID);
static const struct bt_uuid_128 REMOVE_OLD_MASTER_KEY_CHARC_UUID = LOCAL_BT_UUID_CHARC(BT_REMOVE_OLD_MASTER_KEY_CHARC_UUID);
static const struct bt_uuid_128 RESET_CHARC_UUID = LOCAL_BT_UUID_CHARC(BT_RESET_CHARC_UUID);

BT_GATT_SERVICE_DEFINE(g_auth_bt_service,
BT_GATT_PRIMARY_SERVICE(&SERVICE_UUID),
BT_GATT_CHARACTERISTIC(&STATUS_CHARC_UUID.uuid,
    BT_GATT_CHRC_READ,
    BT_GATT_PERM_READ,
    auth_bt_status_read_cb, NULL, NULL),
BT_GATT_CHARACTERISTIC(&ACTIVATE_CHARC_UUID.uuid,
    BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE,
    BT_GATT_PERM_WRITE_ENCRYPT,
    NULL, auth_bt_activate_write_cb, NULL),
BT_GATT_CHARACTERISTIC(&AUTH_CHARC_UUID.uuid,
    BT_GATT_CHRC_WRITE,
    BT_GATT_PERM_WRITE_ENCRYPT,
    NULL, auth_bt_auth_write_cb, NULL),
BT_GATT_CHARACTERISTIC(&IDENTITY_KEY_CHARC_UUID.uuid,
    BT_GATT_CHRC_WRITE,
    BT_GATT_PERM_WRITE_ENCRYPT,
    NULL, auth_bt_identity_key_write_cb, NULL),
BT_GATT_CHARACTERISTIC(&IDENTITY_CHALLENGE_CHARC_UUID.uuid,
    BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE,
    BT_GATT_PERM_WRITE_ENCRYPT | BT_GATT_PERM_READ_ENCRYPT,
    auth_bt_identity_challenge_read_cb, auth_bt_identity_challenge_write_cb, NULL),
BT_GATT_CHARACTERISTIC(&USED_CERTS_CHARC_UUID.uuid,
    BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE,
    BT_GATT_PERM_WRITE_ENCRYPT | BT_GATT_PERM_READ_ENCRYPT,
    auth_bt_used_certs_read_cb, auth_bt_used_certs_write_cb, NULL),
BT_GATT_CHARACTERISTIC(&REVOKE_CERT_CHARC_UUID.uuid,
    BT_GATT_CHRC_WRITE,
    BT_GATT_PERM_WRITE_ENCRYPT,
    NULL, auth_bt_revoke_cert_write_cb, NULL),
BT_GATT_CHARACTERISTIC(&ROTATE_MASTER_KEY_CHARC_UUID.uuid,
    BT_GATT_CHRC_WRITE,
    BT_GATT_PERM_WRITE_ENCRYPT,
    NULL, auth_bt_rotate_master_key_write_cb, NULL),
BT_GATT_CHARACTERISTIC(&REMOVE_OLD_MASTER_KEY_CHARC_UUID.uuid,
    BT_GATT_CHRC_WRITE,
    BT_GATT_PERM_WRITE_ENCRYPT,
    NULL, auth_bt_remove_old_master_key_write_cb, NULL),
BT_GATT_CHARACTERISTIC(&RESET_CHARC_UUID.uuid,
    BT_GATT_CHRC_WRITE,
    BT_GATT_PERM_WRITE_ENCRYPT,
    NULL, auth_bt_reset_write_cb, NULL),
);

SETTINGS_STATIC_HANDLER_DEFINE(auth, "auth", NULL, auth_settings_set, NULL, NULL);

static inline bool is_nvs_id_set(nvs_cert_id_t const nvs_id) {
    return nvs_id > 0;
}

static inline bool is_str_set(char const* const str) {
    return 0 != str[0];
}

static inline bool is_bin_set(uint8_t const* const data, uint8_t const size) {
    for (uint8_t i = 0; i < size; i++) {
        if (0 != data[i]) {
            return true;
        }
    }

    return false;
}

static inline bool is_salt_set(uint8_t const* const salt) {
    return is_bin_set(salt, AUTH_SALT_SIZE);
}

static inline bool is_pub_key_set(uint8_t const* const pub_key) {
    return is_bin_set(pub_key, AUTH_PUB_KEY_SIZE);
}

static inline bool is_activated(void) {
    return PSA_KEY_ID_NULL != g_master_pub_key_id;
}

static inline bool is_rotation_proceeded(void) {
    return is_pub_key_set(g_master_pub_key_old);
}

static inline nvs_cert_id_t generate_next_cert_local_storage_id(void) {
    for (uint16_t i = 0; i < CONFIG_AUTH_BLE_MAX_LOCAL_CERTS; i++) {
        if (!is_salt_set(g_local_cert_ids[i].salt)) {
            return i + 1;
        }
    }

    return 0;
}

static inline nvs_cert_id_t find_cert_id_in_local_storage(uint8_t const* const salt) {
    for (uint16_t i = 0; i < CONFIG_AUTH_BLE_MAX_LOCAL_CERTS; i++) {
        if (0 == memcmp(salt, g_local_cert_ids[i].salt, sizeof(g_local_cert_ids[i].salt))) {
            return i + 1;
        }
    }

    return 0;
}

static inline bool is_time_to_update_cert_last_use(unix_timestamp_t const last_use) {
    /// TODO: As UTC time was implemented.
    UNUSED(CERT_LAST_USE_UPDATE_THRESHOLD);
    return false;
}

static inline int assert_auth_conn_and_privileges(struct AuthConn const* const auth_conn, privileges_t const to_check) {
    int rc = 0;

    ASSERTs(NULL != auth_conn, ER_NO_DEV);
    ASSERTs(AUTH_CONN_STATUS__PASSED == auth_conn->status, ER_NOT_PERM);
    ASSERTs(auth_conn->cert.privileges & to_check, ER_NOT_PERM);

 finally:
    return rc;
}

static int auth_settings_set(
    char const* const name,
    size_t const len,
    settings_read_cb const read_cb,
    void* const cb_arg)
{
    int rc = 0;

    if (strcmp(name, SETTINGS_KEY_MASTER_PUB_KEY) == 0) {
        ASSERT(sizeof(g_master_pub_key) == len, ER_INVAL);
        rc = read_cb(cb_arg, g_master_pub_key, len);
        goto finally;
    }
    if (strcmp(name, SETTINGS_KEY_MASTER_PUB_KEY_OLD) == 0) {
        ASSERT(sizeof(g_master_pub_key_old) == len, ER_INVAL);
        rc = read_cb(cb_arg, g_master_pub_key_old, len);
        goto finally;
    }

    rc = ER_NO_ENT;

 finally:
    return rc;
}

static int save_all_settings(void) {
    int rc = 0;

    TRY(settings_save_one(SETTINGS_KEY_MASTER_PUB_KEY_FULL, g_master_pub_key, sizeof(g_master_pub_key)));
    TRY(settings_save_one(SETTINGS_KEY_MASTER_PUB_KEY_OLD_FULL, g_master_pub_key_old, sizeof(g_master_pub_key_old)));

 finally:
    return rc;
}

static struct AuthConn* find_auth_conn(struct bt_conn const* const conn) {
    for (uint8_t i = 0; i < CONFIG_BT_MAX_CONN; i++) {
        if (conn == g_auth_conns[i].conn) {
            return &g_auth_conns[i];
        }
    }

    return NULL;
}

static void _on_bt_event(struct zbus_channel const* const chan)
{
    struct ZtlBtEvent const* const evt = zbus_chan_msg(chan);

    if (ZTL_BT_EVENT__CONNECTED == evt->type) {
        bool is_auth_conn_set = false;
        k_mutex_lock(&g_mutex, K_FOREVER);

        for (uint8_t i = 0; i < CONFIG_BT_MAX_CONN; i++) {
            if (NULL == g_auth_conns[i].conn) {
                g_auth_conns[i].conn = evt->conn;
                is_auth_conn_set = true;
                break;
            }
        }

        k_mutex_unlock(&g_mutex);

        if (!is_auth_conn_set) {
            LOG_ERR("Fail to found free auth_conn: disconnect..");
            TRY_PASS(bt_conn_disconnect(evt->conn, BT_HCI_ERR_REMOTE_LOW_RESOURCES));
        }
    } else if (ZTL_BT_EVENT__DISCONNECTED == evt->type) {
        k_mutex_lock(&g_mutex, K_FOREVER);

        struct AuthConn* const auth_conn = find_auth_conn(evt->conn);
        if (auth_conn) {
            memset(auth_conn, 0, sizeof(*auth_conn));
        }

        k_mutex_unlock(&g_mutex);
    }
}

static ssize_t auth_bt_status_read_cb(
    struct bt_conn *const conn,
    struct bt_gatt_attr const* const attr,
	void* const buf,
    uint16_t const len,
	uint16_t const offset)
{
    int rc = 0;
    uint8_t* const buf_u8 = buf;

    ASSERT(len >= sizeof(uint8_t)*2, BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN));

    k_mutex_lock(&g_mutex, K_FOREVER);

    buf_u8[0] = (uint8_t)g_auth_status;
    struct AuthConn* const auth_conn = find_auth_conn(conn);
    if (auth_conn) {
        buf_u8[1] = auth_conn->status;
    }

    rc = sizeof(uint8_t) * 2;

 finally:
    k_mutex_unlock(&g_mutex);

    return rc;
}

static inline int reimport_pub_key(psa_key_id_t* const pub_key_id, uint8_t const* const pub_key) {
    int rc = 0;

    if (PSA_KEY_ID_NULL != *pub_key_id) {
        TRY(psa_destroy_key(*pub_key_id));
    }

    psa_key_attributes_t key_attrs = psa_key_attributes_init();
    psa_set_key_usage_flags(&key_attrs, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_lifetime(&key_attrs, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_algorithm(&key_attrs, PSA_ALG_PURE_EDDSA);
    psa_set_key_type(&key_attrs, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&key_attrs, AUTH_PUB_KEY_SIZE * 8);
    TRY(psa_import_key(&key_attrs, pub_key, AUTH_PUB_KEY_SIZE, pub_key_id));

 finally:
    return rc;
}

/** @brief Десериализовать структуру AuthLocalCert.
 * Формат сериализованной структуры:
 * salt: u8[16]
 * tlv: u8[]
 */
static int deserialize_local_cert(uint8_t const* const buf, uint16_t const size, struct AuthLocalCert* cert) {
    int rc = 0;

    ASSERT(size > sizeof(cert->salt), ER_INVAL);

    memcpy(cert->salt, buf, sizeof(cert->salt));

    struct TlvScan tlv_scan = {0};
    TRY(tlv__scan_init(&tlv_scan, buf + sizeof(cert->salt), size - sizeof(cert->salt)));

    while (true) {
        struct Tlv const* const tlv = tlv__next(&tlv_scan);
        if (NULL == tlv) {
            break;
        }
        if (AUTH_TLV_TAG__USER_NAME == tlv->tag) {
            TRY(tlv__to_str(tlv, cert->user_name, sizeof(cert->user_name)));
        } else if (AUTH_TLV_TAG__PRIVILEGES == tlv->tag) {
            ASSERT(sizeof(cert->privileges) == tlv->len, ER_INVAL);
            cert->privileges = *((privileges_t const*)tlv->data);
        } else if (AUTH_TLV_TAG__VALID_FROM == tlv->tag) {
            ASSERT(sizeof(cert->valid_from) == tlv->len, ER_INVAL);
            cert->valid_from = *((unix_timestamp_t const*)tlv->data);
        } else if (AUTH_TLV_TAG__VALID_TO == tlv->tag) {
            ASSERT(sizeof(cert->valid_to) == tlv->len, ER_INVAL);
            cert->valid_to = *((unix_timestamp_t const*)tlv->data);
        } else if (AUTH_TLV_TAG__VALID_WEEK_DAYS == tlv->tag) {
            ASSERT(sizeof(cert->valid_week_days) == tlv->len, ER_INVAL);
            cert->valid_week_days = *((week_days_t const*)tlv->data);
        } else if (AUTH_TLV_TAG__LAST_USE == tlv->tag) {
            ASSERT(sizeof(cert->last_use) == tlv->len, ER_INVAL);
            cert->last_use = *((unix_timestamp_t const*)tlv->data);
        } else if (AUTH_TLV_TAG__VALID_STATE == tlv->tag) {
            ASSERT(sizeof(cert->valid_state) == tlv->len, ER_INVAL);
            cert->valid_state = (enum AuthCertValidState)*tlv->data;
        } else if (AUTH_TLV_TAG__IDENTITY_KEY == tlv->tag) {
            ASSERT(sizeof(cert->identity_key) == tlv->len, ER_INVAL);
            memcpy(cert->identity_key, tlv->data, sizeof(cert->identity_key));
        }
    }

 finally:
    return rc;
}

static int serialize_local_cert(
    uint8_t* const buf,
    uint16_t const size,
    struct AuthLocalCert const* const cert,
    uint16_t* const cert_real_size)
{
    int rc = 0;

    ASSERT(size > sizeof(cert->salt), ER_OVERFLOW);
    memcpy(buf, cert->salt, sizeof(cert->salt));
    struct TlvCreator tlv_creator = {0};

    TRY(tlv__creator_init(&tlv_creator, buf, size - sizeof(cert->salt)));

    if (is_pub_key_set(cert->identity_key)) {
        TRY(tlv__add_tag_data(&tlv_creator, AUTH_TLV_TAG__IDENTITY_KEY, cert->identity_key, sizeof(cert->identity_key)));
    }
    TRY(tlv__add_tag_u32(&tlv_creator, AUTH_TLV_TAG__PRIVILEGES, cert->privileges));
    if (is_str_set(cert->user_name)) {
        TRY(tlv__add_tag_str(&tlv_creator, AUTH_TLV_TAG__USER_NAME, cert->user_name, sizeof(cert->user_name)));
    }
    if (cert->valid_from > 0) {
        TRY(tlv__add_tag_u64(&tlv_creator, AUTH_TLV_TAG__VALID_FROM, cert->valid_from));
    }
    if (cert->valid_to > 0) {
        TRY(tlv__add_tag_u64(&tlv_creator, AUTH_TLV_TAG__VALID_TO, cert->valid_to));
    }
    if (cert->valid_week_days > 0) {
        TRY(tlv__add_tag_u8(&tlv_creator, AUTH_TLV_TAG__VALID_WEEK_DAYS, cert->valid_week_days));
    }
    TRY(tlv__add_tag_u8(&tlv_creator, AUTH_TLV_TAG__VALID_STATE, cert->valid_state));
    if (cert->last_use > 0) {
        TRY(tlv__add_tag_u64(&tlv_creator, AUTH_TLV_TAG__LAST_USE, cert->last_use));
    }

    *cert_real_size = tlv__get_real_buf_size(&tlv_creator);

 finally:
    return rc;
}

static ssize_t auth_bt_activate_write_cb(
    struct bt_conn* const conn,
    struct bt_gatt_attr const* const attr,
    void const* const buf,
    uint16_t const len,
    uint16_t const offset,
    uint8_t const flags)
{
    int rc = 0;

    ASSERT(AUTH_PUB_KEY_SIZE == len, BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN));
    ASSERT(auth__status() == AUTH_GLOBAL_STATUS__NOT_ACTIVATED, BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED));

    k_mutex_lock(&g_mutex, K_FOREVER);

    TRYr(reimport_pub_key(&g_master_pub_key_id, buf), BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));

    TRYr(save_all_settings(), BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));

    atomic_set(&g_auth_status, AUTH_GLOBAL_STATUS__OK);

 finally:

    k_mutex_unlock(&g_mutex);

    return len;
}

static int assert_cert_restriction(struct AuthConn const* const auth_conn) {
    int rc = 0;

    ASSERTs(AUTH_CERT_VALID_STATE__INVALID != auth_conn->cert.valid_state, ER_NOT_PERM);

    /// TODO: As UTC time was implemented. Check valid_from/to, week_days.

 finally:
    return rc;
}

static ssize_t auth_bt_auth_write_cb(
    struct bt_conn* const conn,
    struct bt_gatt_attr const* const attr,
    void const* const buf,
    uint16_t const len,
    uint16_t const offset,
    uint8_t const flags)
{
    int rc = 0;
    ASSERT(len > AUTH_SIGN_SIZE + AUTH_SALT_SIZE, BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN));
    ASSERT(0 == offset, BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET));
    ASSERT(auth__status() == AUTH_GLOBAL_STATUS__OK, BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED));

    k_mutex_lock(&g_mutex, K_FOREVER);

    struct AuthConn* const auth_conn = find_auth_conn(conn);
    ASSERT(NULL != auth_conn, BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));
    ASSERT(AUTH_CONN_STATUS__WAIT_CERT == auth_conn->status, BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED));

    uint8_t const* const sign = buf;
    uint8_t const* const cert_data = sign + AUTH_SIGN_SIZE;
    uint16_t const cert_data_size = len - AUTH_SIGN_SIZE;

    rc = psa_verify_message(g_master_pub_key_id, PSA_ALG_PURE_EDDSA, cert_data, cert_data_size, sign, AUTH_SIGN_SIZE);

    if (0 != rc) {
        ASSERT(PSA_KEY_ID_NULL != g_master_pub_key_old_id, BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED));

        TRYr(psa_verify_message(
            g_master_pub_key_old_id, PSA_ALG_PURE_EDDSA, cert_data, cert_data_size, sign, AUTH_SIGN_SIZE),
            BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED));
    }

    // salt - first field of cert_data.
    auth_conn->cert_nvs_id = find_cert_id_in_local_storage(cert_data);

    if (is_nvs_id_set(auth_conn->cert_nvs_id)) {
        // Already used and found in storage - fill from it.
        uint8_t cert_buf[AUTH_LOCAL_CERT_BUF_SIZE] = {0};
        ssize_t const check = nvs_read(&g_cert_storage_nvs, auth_conn->cert_nvs_id, cert_buf, sizeof(cert_buf));
        ASSERT(check > 0, BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));
        TRYr(deserialize_local_cert(cert_buf, (uint16_t)check, &auth_conn->cert),
            BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED));
        TRYr(assert_cert_restriction(auth_conn), BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED));
        auth_conn->status = AUTH_CONN_STATUS__WAIT_IDENTITY_CHALLENGE;
    } else {
        // First use - fill from tlv.
        TRYr(deserialize_local_cert(cert_data, cert_data_size, &auth_conn->cert),
            BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED));
        ASSERT(is_str_set(auth_conn->cert.user_name), BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED));
        ASSERT(0 != auth_conn->cert.privileges, BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED));
        TRYr(assert_cert_restriction(auth_conn), BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED));
        memcpy(auth_conn->cert.salt, cert_data, AUTH_SALT_SIZE);
        auth_conn->status = AUTH_CONN_STATUS__WAIT_IDENTITY_KEY;
    }

    rc = len;

 finally:

    k_mutex_unlock(&g_mutex);

    return rc;
}

static ssize_t auth_bt_identity_key_write_cb(
    struct bt_conn* const conn,
    struct bt_gatt_attr const* const attr,
    void const* const buf,
    uint16_t const len,
    uint16_t const offset,
    uint8_t const flags)
{
    int rc = 0;

    ASSERT(AUTH_PUB_KEY_SIZE == len, BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN));
    ASSERT(0 == offset, BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET));

    k_mutex_lock(&g_mutex, K_FOREVER);

    struct AuthConn* const auth_conn = find_auth_conn(conn);
    ASSERT(NULL != auth_conn, BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));
    ASSERT(AUTH_CONN_STATUS__WAIT_IDENTITY_KEY == auth_conn->status, BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED));
    memcpy(auth_conn->cert.identity_key, buf, sizeof(auth_conn->cert.identity_key));
    auth_conn->status = AUTH_CONN_STATUS__WAIT_IDENTITY_CHALLENGE;

    rc = len;

 finally:

    k_mutex_unlock(&g_mutex);

    return rc;
}

static ssize_t auth_bt_identity_challenge_read_cb(
    struct bt_conn *const conn,
    struct bt_gatt_attr const* const attr,
	void* const buf,
    uint16_t const len,
	uint16_t const offset)
{
    int rc = 0;

    ASSERT(len >= AUTH_SALT_SIZE, BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN));
    ASSERT(0 == offset, BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET));

    k_mutex_lock(&g_mutex, K_FOREVER);

    struct AuthConn* const auth_conn = find_auth_conn(conn);
    ASSERT(NULL != auth_conn, BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));
    ASSERT(AUTH_CONN_STATUS__WAIT_IDENTITY_CHALLENGE == auth_conn->status,
        BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED));

    TRYr(psa_generate_random(auth_conn->identity_rand, sizeof(auth_conn->identity_rand)),
        BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));

    rc = len;

 finally:

    k_mutex_unlock(&g_mutex);

    return rc;
}

static ssize_t auth_bt_identity_challenge_write_cb(
    struct bt_conn* const conn,
    struct bt_gatt_attr const* const attr,
    void const* const buf,
    uint16_t const len,
    uint16_t const offset,
    uint8_t const flags)
{
    int rc = 0;

    ASSERT(AUTH_SIGN_SIZE == len, BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN));
    ASSERT(0 == offset, BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET));

    k_mutex_lock(&g_mutex, K_FOREVER);

    struct AuthConn* const auth_conn = find_auth_conn(conn);
    ASSERT(NULL != auth_conn, BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));
    ASSERT(AUTH_CONN_STATUS__WAIT_IDENTITY_CHALLENGE == auth_conn->status,
        BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED));
    ASSERT(is_salt_set(auth_conn->identity_rand), BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED));

    TRYr(psa_verify_message(g_master_pub_key_id, PSA_ALG_PURE_EDDSA, auth_conn->identity_rand,
        sizeof(auth_conn->identity_rand), buf, len), 0);

    bool const is_cert_exists_in_local_storage = is_nvs_id_set(auth_conn->cert_nvs_id);
    if (!is_cert_exists_in_local_storage || is_time_to_update_cert_last_use(auth_conn->cert.last_use)) {
        if (!is_cert_exists_in_local_storage) {
            auth_conn->cert_nvs_id = generate_next_cert_local_storage_id();
            ASSERT(is_nvs_id_set(auth_conn->cert_nvs_id), BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));
        }
        uint8_t buf[AUTH_LOCAL_CERT_BUF_SIZE] = {0};
        uint16_t cert_real_size = 0;
        TRYr(serialize_local_cert(buf, sizeof(buf), &auth_conn->cert, &cert_real_size),
            BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));
        ssize_t const check = nvs_write(&g_cert_storage_nvs, auth_conn->cert_nvs_id, buf, cert_real_size);
        ASSERT(check == cert_real_size, BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));
    }

    auth_conn->status = AUTH_CONN_STATUS__PASSED;

    rc = len;

 finally:

    k_mutex_unlock(&g_mutex);

    return rc;
}

static ssize_t auth_bt_used_certs_read_cb(
    struct bt_conn* const conn,
    const struct bt_gatt_attr* const attr,
	void* const buf,
    uint16_t const len,
	uint16_t const offset)
{
    int rc = 0;

    ASSERT(0 == offset, BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET));

    k_mutex_lock(&g_mutex, K_FOREVER);

    struct AuthConn* const auth_conn = find_auth_conn(conn);
    TRYr(assert_auth_conn_and_privileges(auth_conn, AUTH_PRIVILEGES__READ_CERTS_USAGE_HISTORY),
        BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED));
    ASSERT(auth_conn->used_certs_ptr < CONFIG_AUTH_BLE_MAX_LOCAL_CERTS,
        BT_GATT_ERR(BT_ATT_ERR_OUT_OF_RANGE));

    ssize_t const check = nvs_read(&g_cert_storage_nvs, auth_conn->used_certs_ptr + 1, buf, len);
    ASSERT(check > 0 && check < len, BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));

    auth_conn->used_certs_ptr += 1;
    rc = check;

 finally:

    k_mutex_unlock(&g_mutex);

    return rc;
}

static ssize_t auth_bt_used_certs_write_cb(
    struct bt_conn* const conn,
    const struct bt_gatt_attr* const attr,
    const void* const buf,
    uint16_t const len,
    uint16_t const offset,
    uint8_t const flags)
{
    int rc = 0;

    ASSERT(sizeof(uint16_t) == len, BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN));
    ASSERT(0 == offset, BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET));

    k_mutex_lock(&g_mutex, K_FOREVER);

    struct AuthConn* const auth_conn = find_auth_conn(conn);
    TRYr(assert_auth_conn_and_privileges(auth_conn, AUTH_PRIVILEGES__READ_CERTS_USAGE_HISTORY),
        BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED));

    auth_conn->used_certs_ptr = *((uint16_t const*)buf);

    rc = len;

 finally:

    k_mutex_unlock(&g_mutex);

    return rc;
}

static ssize_t auth_bt_revoke_cert_write_cb(
    struct bt_conn* const conn,
    const struct bt_gatt_attr* const attr,
    const void* const buf,
    uint16_t const len,
    uint16_t const offset,
    uint8_t const flags)
{
    int rc = 0;

    ASSERT(AUTH_SALT_SIZE == len, BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN));
    ASSERT(0 == offset, BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET));

    k_mutex_lock(&g_mutex, K_FOREVER);

    struct AuthConn* const auth_conn = find_auth_conn(conn);
    TRYr(assert_auth_conn_and_privileges(auth_conn, AUTH_PRIVILEGES__CERTS_MANAGE),
        BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED));

    nvs_cert_id_t nvs_cert_id = find_cert_id_in_local_storage(buf);
    struct AuthLocalCert cert = {0};
    uint8_t cert_buf[AUTH_LOCAL_CERT_BUF_SIZE] = {0};

    if (is_nvs_id_set(nvs_cert_id)) {
        ssize_t check = nvs_read(&g_cert_storage_nvs, nvs_cert_id, cert_buf, sizeof(cert_buf));
        ASSERT(check > 0, BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));
        TRYr(deserialize_local_cert(cert_buf, (uint16_t)check, &cert),
            BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));
        TRYr(memcmp(cert.salt, buf, sizeof(cert.salt)),
            BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));
    } else {
        nvs_cert_id = generate_next_cert_local_storage_id();
        ASSERT(is_nvs_id_set(nvs_cert_id), BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));
        memcpy(cert.salt, buf, sizeof(cert.salt));
    }

    cert.valid_state = AUTH_CERT_VALID_STATE__INVALID;
    uint16_t cert_real_size = 0;
    TRYr(serialize_local_cert(cert_buf, sizeof(cert_buf), &cert, &cert_real_size),
        BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));
    ssize_t const check = nvs_write(&g_cert_storage_nvs, nvs_cert_id, cert_buf, cert_real_size);
    ASSERT(check == cert_real_size, BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));

    rc = len;

 finally:

    k_mutex_unlock(&g_mutex);

    return rc;
}

static ssize_t auth_bt_rotate_master_key_write_cb(
    struct bt_conn* const conn,
    const struct bt_gatt_attr* const attr,
    const void* const buf,
    uint16_t const len,
    uint16_t const offset,
    uint8_t const flags)
{
    int rc = 0;

    ASSERT(AUTH_PUB_KEY_SIZE == len, BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN));
    ASSERT(0 == offset, BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET));

    k_mutex_lock(&g_mutex, K_FOREVER);

    struct AuthConn* const auth_conn = find_auth_conn(conn);
    TRYr(assert_auth_conn_and_privileges(auth_conn, AUTH_PRIVILEGES__ROTATE_MASTER_KEY),
        BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED));
    ASSERT(!is_rotation_proceeded(), BT_GATT_ERR(BT_ATT_ERR_PROCEDURE_IN_PROGRESS));

    memcpy(g_master_pub_key_old, g_master_pub_key, sizeof(g_master_pub_key_old));
    memcpy(g_master_pub_key, buf, sizeof(g_master_pub_key));
    TRYr(reimport_pub_key(&g_master_pub_key_id, g_master_pub_key),
        BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));
    TRYr(reimport_pub_key(&g_master_pub_key_old_id, g_master_pub_key_old),
        BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));

    TRYr(save_all_settings(), BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));

    // Clear invalid certs in local storage, mark else as valid_old.
    for (uint16_t i = 0; i < CONFIG_AUTH_BLE_MAX_LOCAL_CERTS; i++) {
        uint8_t buf[AUTH_LOCAL_CERT_BUF_SIZE] = {0};
        nvs_cert_id_t const nvs_cert_id = i + 1;
        ssize_t const check = nvs_read(&g_cert_storage_nvs, nvs_cert_id, buf, sizeof(buf));
        if (check > AUTH_SALT_SIZE) {
            struct AuthLocalCert cert = {0};
            int const check_deser = deserialize_local_cert(buf, (uint16_t)check, &cert);
            if (0 == check_deser) {
                if (AUTH_CERT_VALID_STATE__INVALID == cert.valid_state) {
                    TRY_PASS(nvs_delete(&g_cert_storage_nvs, nvs_cert_id));
                    memset(g_local_cert_ids[i].salt, 0, sizeof(g_local_cert_ids[i].salt));
                } else if (AUTH_CERT_VALID_STATE__VALID == cert.valid_state) {
                    cert.valid_state = AUTH_CERT_VALID_STATE__VALID_OLD;
                    uint16_t cert_real_size = 0;
                    TRYr(serialize_local_cert(buf, sizeof(buf), &cert, &cert_real_size),
                        BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));
                    ssize_t const check = nvs_write(&g_cert_storage_nvs, nvs_cert_id, buf, cert_real_size);
                    ASSERT(check == cert_real_size, BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));
                }
            }
        }
    }

    rc = len;

 finally:

    k_mutex_unlock(&g_mutex);

    return rc;
}

static ssize_t auth_bt_remove_old_master_key_write_cb(
    struct bt_conn* const conn,
    const struct bt_gatt_attr* const attr,
    const void* const buf,
    uint16_t const len,
    uint16_t const offset,
    uint8_t const flags)
{
    int rc = 0;

    ASSERT(sizeof(uint8_t) == len, BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN));
    ASSERT(0 == offset, BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET));
    ASSERT(1 == *(uint8_t const*)buf, BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED));

    k_mutex_lock(&g_mutex, K_FOREVER);

    struct AuthConn* const auth_conn = find_auth_conn(conn);
    TRYr(assert_auth_conn_and_privileges(auth_conn, AUTH_PRIVILEGES__ROTATE_MASTER_KEY),
        BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED));
    ASSERT(is_rotation_proceeded(), BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED));

    memset(g_master_pub_key_old, 0, sizeof(g_master_pub_key_old));
    if (PSA_KEY_ID_NULL != g_master_pub_key_old_id) {
        TRY_PASS(psa_destroy_key(g_master_pub_key_old_id));
    }

    TRYr(save_all_settings(), BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));

    // Remove old key certs in local storage.
    for (uint16_t i = 0; i < CONFIG_AUTH_BLE_MAX_LOCAL_CERTS; i++) {
        uint8_t buf[AUTH_LOCAL_CERT_BUF_SIZE] = {0};
        ssize_t const check = nvs_read(&g_cert_storage_nvs, i + 1, buf, sizeof(buf));
        if (check > AUTH_SALT_SIZE) {
            struct AuthLocalCert cert = {0};
            int const check_deser = deserialize_local_cert(buf, (uint16_t)check, &cert);
            if (0 == check_deser) {
                if (AUTH_CERT_VALID_STATE__VALID_OLD == cert.valid_state ||
                    AUTH_CERT_VALID_STATE__INVALID == cert.valid_state)
                {
                    TRY_PASS(nvs_delete(&g_cert_storage_nvs, i + 1));
                    memset(g_local_cert_ids[i].salt, 0, sizeof(g_local_cert_ids[i].salt));
                }
            }
        }
    }

    rc = len;

 finally:

    k_mutex_unlock(&g_mutex);

    return rc;
}

static ssize_t auth_bt_reset_write_cb(
    struct bt_conn* const conn,
    const struct bt_gatt_attr* const attr,
    const void* const buf,
    uint16_t const len,
    uint16_t const offset,
    uint8_t const flags)
{
    int rc = 0;

    ASSERT(sizeof(uint8_t) == len, BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN));
    ASSERT(0 == offset, BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET));
    ASSERT(1 == *(uint8_t const*)buf, BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED));

    k_mutex_lock(&g_mutex, K_FOREVER);

    struct AuthConn* const auth_conn = find_auth_conn(conn);
    TRYr(assert_auth_conn_and_privileges(auth_conn, AUTH_PRIVILEGES__RESET_AUTH),
        BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED));

    TRY_PASS(psa_destroy_key(g_master_pub_key_id));
    if (PSA_KEY_ID_NULL != g_master_pub_key_old_id) {
        TRY_PASS(psa_destroy_key(g_master_pub_key_old_id));
    }

    memset(g_master_pub_key, 0, sizeof(g_master_pub_key));
    memset(g_master_pub_key_old, 0, sizeof(g_master_pub_key_old));
    TRYr(save_all_settings(), BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES));

    atomic_set(&g_auth_status, AUTH_GLOBAL_STATUS__NOT_ACTIVATED);

 finally:

    k_mutex_unlock(&g_mutex);

    return rc;
}

int auth__init(void) {
    int rc = 0;

    TRY(psa_crypto_init());
    TRY(ztl_nvs__init(&g_cert_storage_nvs, auth_cert_storage_partition));

    k_mutex_lock(&g_mutex, K_FOREVER);

    if (is_pub_key_set(g_master_pub_key)) {
        TRY(reimport_pub_key(&g_master_pub_key_id, g_master_pub_key));
        if (is_pub_key_set(g_master_pub_key_old)) {
            TRY(reimport_pub_key(&g_master_pub_key_old_id, g_master_pub_key_old));
        }
    }

    for (uint16_t i = 0; i < CONFIG_AUTH_BLE_MAX_LOCAL_CERTS; i++) {
        uint8_t buf[AUTH_LOCAL_CERT_BUF_SIZE] = {0};
        ssize_t const check = nvs_read(&g_cert_storage_nvs, i + 1, buf, sizeof(buf));
        if (check > AUTH_SALT_SIZE) {
            struct AuthLocalCert cert = {0};
            int const check_deser = deserialize_local_cert(buf, (uint16_t)check, &cert);
            if (0 == check_deser) {
                memcpy(g_local_cert_ids[i].salt, cert.salt, sizeof(g_local_cert_ids[i].salt));
            }
        }
    }

    if (is_activated()) {
        atomic_set(&g_auth_status, AUTH_GLOBAL_STATUS__OK);
    } else {
        atomic_set(&g_auth_status, AUTH_GLOBAL_STATUS__NOT_ACTIVATED);
    }

    TRY(zbus_chan_add_obs(&e_ztl_bt_chan, &g_auth_bt_listener, K_FOREVER));

 finally:

    k_mutex_unlock(&g_mutex);

    return rc;
}

int auth__privileges(struct bt_conn const* const conn, privileges_t* const privileges) {
    int rc = 0;

    k_mutex_lock(&g_mutex, K_FOREVER);
    if (AUTH_GLOBAL_STATUS__NOT_ACTIVATED == auth__status()) {
        *privileges = AUTH_PRIVILEGES_ALL;
    } else {
        struct AuthConn const* const auth_conn = find_auth_conn(conn);
        ASSERTs(NULL != auth_conn, ER_NO_ENT);
        ASSERT(AUTH_CONN_STATUS__PASSED == auth_conn->status, ER_NOT_PERM);
        *privileges = auth_conn->cert.privileges;
    }

 finally:

    k_mutex_unlock(&g_mutex);

    return rc;
}

int auth__assert_privileges(struct bt_conn const* const conn, privileges_t const to_check) {
    int rc = 0;
    privileges_t current = 0;

    TRY(auth__privileges(conn, &current));
    ASSERTs(current & to_check, ER_NOT_PERM);

 finally:
    return rc;
}

enum AuthGlobalStatus auth__status(void) {
    return (enum AuthGlobalStatus)atomic_get(&g_auth_status);
}

int auth__cert_id(struct bt_conn const* conn, struct AuthLocalCertId* cert_id) {
    int rc = 0;

    struct AuthConn const* const auth_conn = find_auth_conn(conn);
    ASSERTs(NULL != auth_conn, ER_NO_ENT);
    ASSERTs(is_salt_set(auth_conn->cert.salt), ER_NO_DATA);
    memcpy(cert_id->salt, auth_conn->cert.salt, sizeof(cert_id->salt));

 finally:
    return rc;
}
