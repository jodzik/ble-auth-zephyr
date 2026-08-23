#ifndef AUTH_H_
#define AUTH_H_

#include <ztl/bt.h>
#include <ztl/ztl_time.h>

#include <zephyr/kernel.h>

#include <stdbool.h>

#define AUTH_PRIVILEGE(privilege_idx) (1U << (privilege_idx + 4))

typedef uint8_t week_days_t;
typedef uint32_t privileges_t;

enum {
    AUTH_PRIVILEGES_ALL = 0xFFFFFFFF,

    AUTH_PUB_KEY_SIZE = 32,
    AUTH_SIGN_SIZE = 64,
    AUTH_SALT_SIZE = 16,
    AUTH_CERT_USER_DATA_OFFSET = AUTH_SIGN_SIZE + AUTH_SALT_SIZE,
    AUTH_USER_NAME_SIZE = 64,
    AUTH_LOCAL_CERT_BUF_SIZE = 128,
};

/// @brief Привилегии пользователя для самого сервиса AAA, битовая маска.
enum AuthPrivileges {
    AUTH_PRIVILEGES__READ_CERTS_USAGE_HISTORY = 1U << 0,
    AUTH_PRIVILEGES__CERTS_MANAGE = 1U << 1,
    AUTH_PRIVILEGES__ROTATE_MASTER_KEY = 1U << 2,
    AUTH_PRIVILEGES__RESET_AUTH = 1U << 3,
};

typedef enum AuthTlvTag {
    AUTH_TLV_TAG__SERIAL = 1,
    AUTH_TLV_TAG__USER_NAME = 2,
    AUTH_TLV_TAG__PRIVILEGES = 3,
    AUTH_TLV_TAG__CREATE_DATETIME = 4,
    AUTH_TLV_TAG__VALID_FROM = 5,
    AUTH_TLV_TAG__VALID_TO = 6,
    AUTH_TLV_TAG__VALID_WEEK_DAYS = 7,

    AUTH_TLV_TAG__LAST_USE = 16,
    AUTH_TLV_TAG__VALID_STATE = 17,
    AUTH_TLV_TAG__IDENTITY_KEY = 18,
} AuthTlvTag;

typedef enum AuthGlobalStatus {
    AUTH_GLOBAL_STATUS__DISABLED = 0,
    AUTH_GLOBAL_STATUS__NOT_ACTIVATED = 1,
    AUTH_GLOBAL_STATUS__OK = 2,
} AuthGlobalStatus;

typedef enum AuthConnStatus {
    AUTH_CONN_STATUS__WAIT_CERT = 0,
    AUTH_CONN_STATUS__WAIT_IDENTITY_KEY = 1,
    AUTH_CONN_STATUS__WAIT_IDENTITY_CHALLENGE = 2,
    AUTH_CONN_STATUS__PASSED = 3,
} AuthConnStatus;

typedef enum AuthCertValidState {
    AUTH_CERT_VALID_STATE__INVALID = 0,
    AUTH_CERT_VALID_STATE__VALID = 1,
    AUTH_CERT_VALID_STATE__VALID_OLD = 2,
} AuthCertValidState;

/// @brief Cert struct from local cert storage.
typedef struct AuthLocalCert {
    uint8_t salt[AUTH_SALT_SIZE];
    char user_name[AUTH_USER_NAME_SIZE];
    privileges_t privileges;
    unix_timestamp_t valid_from;
    unix_timestamp_t valid_to;
    week_days_t valid_week_days;
    unix_timestamp_t last_use;
    enum AuthCertValidState valid_state;
    uint8_t identity_key[AUTH_PUB_KEY_SIZE];
} AuthLocalCert;

typedef struct AuthLocalCertId {
    uint8_t salt[AUTH_SALT_SIZE];
} AuthLocalCertId;

int auth__init(void);

int auth__privileges(struct bt_conn const* conn, privileges_t* privileges);

int auth__assert_privileges(struct bt_conn const* conn, privileges_t to_check);

enum AuthGlobalStatus auth__status(void);

int auth__cert_id(struct bt_conn const* conn, struct AuthLocalCertId* cert_id);

#endif // AUTH_H_
