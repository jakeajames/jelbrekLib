struct profile;
struct sandbox;
struct extension_hdr;
struct extension;

typedef struct extension_hdr* extension_hdr_t;
typedef struct extension* extension_t;

enum ext_type {
    ET_FILE = 0,
    ET_MACH = 1,
    ET_IOKIT_REG_ENT = 2,
    ET_POSIX_IPC = 4,
    ET_PREF_DOMAIN = 5,
    ET_SYSCTL = 6,
};

bool addSandboxExceptionsToPid(pid_t pid, char *ent_key, char **paths);
