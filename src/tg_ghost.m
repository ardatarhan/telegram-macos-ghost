#import <Cocoa/Cocoa.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>

// ============================================================================
// Telegram Desktop 7.3.3 (arm64 macOS) — Static Virtual Addresses (Base 0x100000000)
// ============================================================================

// Trampoline stubs in __TEXT padding (0x100011200 .. 0x100011380)
// Note: stub_va + 0x10 is the direct "call original" entry trampoline!
#define STUB_SEND_READ_REQUESTS     0x100011200ULL
#define STUB_MTP_SEND_REQUEST       0x100011218ULL
#define STUB_SESSION_SEND_PREPARED  0x100011230ULL
#define STUB_BEFORE_DESTROY         0x100011248ULL
#define STUB_ANTI_DELETE            0x100011260ULL
#define STUB_APPLY_EDITION          0x100011278ULL
#define STUB_MEDIA_PHOTO_TTL        0x100011290ULL
#define STUB_MEDIA_FILE_TTL         0x1000112A8ULL
#define STUB_ITEM_ALLOWS_FWD        0x1000112C0ULL
#define STUB_ITEM_ALLOWS_SAVE       0x1000112D8ULL
#define STUB_COPY_RESTR_TYPE        0x1000112F0ULL
#define STUB_INNER_COPY_RESTR       0x100011308ULL
#define STUB_INNER_MEDIA_RESTR      0x100011320ULL
#define STUB_OVERLAY_CAN_SAVE       0x100011338ULL
#define STUB_OVERLAY_SHOW_RESTR     0x100011350ULL
#define STUB_PEER_ALLOWS_FWD        0x100011368ULL

// Original target function addresses
#define VA_SEND_READ_REQUESTS       0x10573950CULL
#define VA_MTP_SEND_REQUEST         0x107C726D0ULL
#define VA_SESSION_SEND_PREPARED    0x107C8B388ULL
#define VA_BEFORE_DESTROY           0x1059244F8ULL
#define VA_DESTROY_MESSAGE          0x106890D74ULL
#define VA_APPLY_EDITION            0x10690B3B4ULL
#define VA_ITEM_ORIGINAL_TEXT       0x1068F1FF8ULL
#define VA_ITEM_SET_TEXT            0x106901050ULL
#define VA_QSTRING_FROM_UTF8        0x101BAC00CULL

// Writable __DATA pointer slots (0x10f840400 .. 0x10f840478)
#define SLOT_SEND_READ_REQUESTS     0x10F840400ULL
#define SLOT_MTP_SEND_REQUEST       0x10F840408ULL
#define SLOT_SESSION_SEND_PREPARED  0x10F840410ULL
#define SLOT_BEFORE_DESTROY         0x10F840418ULL
#define SLOT_ANTI_DELETE            0x10F840420ULL
#define SLOT_APPLY_EDITION          0x10F840428ULL
#define SLOT_MEDIA_TTL              0x10F840430ULL
#define SLOT_ITEM_ALLOWS_FWD        0x10F840438ULL
#define SLOT_ITEM_ALLOWS_SAVE       0x10F840440ULL
#define SLOT_COPY_RESTR_TYPE        0x10F840448ULL
#define SLOT_INNER_COPY_RESTR       0x10F840450ULL
#define SLOT_INNER_MEDIA_RESTR      0x10F840458ULL
#define SLOT_OVERLAY_CAN_SAVE       0x10F840460ULL
#define SLOT_OVERLAY_SHOW_RESTR     0x10F840468ULL
#define SLOT_PEER_ALLOWS_FWD        0x10F840470ULL

// ============================================================================
// MTProto TL Constructor IDs (from scheme.cpp)
// ============================================================================

#define TL_MESSAGES_READ_HISTORY             0x0E306D3AfaU
#define TL_MESSAGES_READ_HISTORY_32          0x0E306D3AU
#define TL_CHANNELS_READ_HISTORY             0xCC104937U
#define TL_MESSAGES_READ_ENCRYPTED_HISTORY   0x7F4B690AU
#define TL_MESSAGES_READ_DISCUSSION          0xF731A9F4U
#define TL_MESSAGES_READ_SAVED_HISTORY       0xBA4A3B5BU
#define TL_MESSAGES_READ_MENTIONS            0x36E5BF4DU
#define TL_MESSAGES_READ_REACTIONS           0x9EC44F93U
#define TL_MESSAGES_READ_POLL_VOTES          0x1720B4D8U
#define TL_MESSAGES_REPORT_READ_METRICS      0x4067C5E6U

#define TL_STORIES_READ_STORIES              0xA556DAC8U

#define TL_MESSAGES_READ_MESSAGE_CONTENTS    0x36A73F77U
#define TL_CHANNELS_READ_MESSAGE_CONTENTS    0xEAB5DC38U

#define TL_MESSAGES_SET_TYPING               0x58943EE2U
#define TL_MESSAGES_SET_ENCRYPTED_TYPING     0x791451EDU

#define TL_MESSAGES_SEND_SCREENSHOT_NOTIFY   0xA1405817U

#define TL_ACCOUNT_UPDATE_STATUS             0x6628562CU
#define TL_BOOL_FALSE                        0xBC799737U
#define TL_BOOL_TRUE                         0x997275B5U

// ============================================================================
// Plugin State & UserDefaults Keys
// ============================================================================

static bool g_block_read          = true;
static bool g_block_stories       = true;
static bool g_block_media         = true;
static bool g_block_typing        = true;
static bool g_hide_online         = false;
static bool g_anti_delete         = true;
static bool g_anti_edit           = true;
static bool g_unlock_restrictions = true;
static bool g_block_screenshot    = true;
static bool g_bypass_ttl          = true;

static volatile uint64_t g_stat_reads      = 0;
static volatile uint64_t g_stat_stories    = 0;
static volatile uint64_t g_stat_media      = 0;
static volatile uint64_t g_stat_typing     = 0;
static volatile uint64_t g_stat_deleted    = 0;
static volatile uint64_t g_stat_edited     = 0;
static volatile uint64_t g_stat_screenshot = 0;

static intptr_t g_aslr_slide = 0;

// Pending read-receipt state for "Mark Last Chat Read Now"
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static void *g_last_histories = NULL;
static void *g_last_history = NULL;
static int32_t g_last_read_till = 0;
static bool g_flushing_now = false;

static void ghost_log(const char *fmt, ...) {
    FILE *fp = fopen("/tmp/tg_ghost.log", "a");
    if (!fp) return;
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    char tbuf[32];
    strftime(tbuf, sizeof(tbuf), "%H:%M:%S", &tm_info);
    fprintf(fp, "[%s] ", tbuf);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    fprintf(fp, "\n");
    fclose(fp);
}

static void load_preferences(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    if ([ud objectForKey:@"TGGhost_BlockRead"] != nil)
        g_block_read = [ud boolForKey:@"TGGhost_BlockRead"];
    if ([ud objectForKey:@"TGGhost_BlockStories"] != nil)
        g_block_stories = [ud boolForKey:@"TGGhost_BlockStories"];
    if ([ud objectForKey:@"TGGhost_BlockMedia"] != nil)
        g_block_media = [ud boolForKey:@"TGGhost_BlockMedia"];
    if ([ud objectForKey:@"TGGhost_BlockTyping"] != nil)
        g_block_typing = [ud boolForKey:@"TGGhost_BlockTyping"];
    if ([ud objectForKey:@"TGGhost_HideOnline"] != nil)
        g_hide_online = [ud boolForKey:@"TGGhost_HideOnline"];
    if ([ud objectForKey:@"TGGhost_AntiDelete"] != nil)
        g_anti_delete = [ud boolForKey:@"TGGhost_AntiDelete"];
    if ([ud objectForKey:@"TGGhost_AntiEdit"] != nil)
        g_anti_edit = [ud boolForKey:@"TGGhost_AntiEdit"];
    if ([ud objectForKey:@"TGGhost_UnlockRestrictions"] != nil)
        g_unlock_restrictions = [ud boolForKey:@"TGGhost_UnlockRestrictions"];
    if ([ud objectForKey:@"TGGhost_BlockScreenshot"] != nil)
        g_block_screenshot = [ud boolForKey:@"TGGhost_BlockScreenshot"];
    if ([ud objectForKey:@"TGGhost_BypassTTL"] != nil)
        g_bypass_ttl = [ud boolForKey:@"TGGhost_BypassTTL"];
}

static void save_preferences(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud setBool:g_block_read forKey:@"TGGhost_BlockRead"];
    [ud setBool:g_block_stories forKey:@"TGGhost_BlockStories"];
    [ud setBool:g_block_media forKey:@"TGGhost_BlockMedia"];
    [ud setBool:g_block_typing forKey:@"TGGhost_BlockTyping"];
    [ud setBool:g_hide_online forKey:@"TGGhost_HideOnline"];
    [ud setBool:g_anti_delete forKey:@"TGGhost_AntiDelete"];
    [ud setBool:g_anti_edit forKey:@"TGGhost_AntiEdit"];
    [ud setBool:g_unlock_restrictions forKey:@"TGGhost_UnlockRestrictions"];
    [ud setBool:g_block_screenshot forKey:@"TGGhost_BlockScreenshot"];
    [ud setBool:g_bypass_ttl forKey:@"TGGhost_BypassTTL"];
    [ud synchronize];
}

// ============================================================================
// Original Function Trampoline Pointers (via __TEXT stubs + 0x10)
// ============================================================================

typedef void (*fn_sendReadRequests_t)(void *histories);
typedef uint64_t (*fn_mtpSendRequest_t)(void *instance, void *serializedReq, void *callbacks,
                                        uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7);
typedef void (*fn_sessionSendPrepared_t)(void *session, void *prepared, int64_t msCanWait);
typedef void (*fn_beforeDestroy_t)(void *session, void **begin, void **end);
typedef void (*fn_destroyMessage_t)(void *history, void *item);
typedef void (*fn_applyEdition_t)(void *item, void *edition);
typedef const void *(*fn_originalText_t)(const void *item);
typedef void (*fn_setText_t)(void *item, const void *textWithEntities);
typedef bool (*fn_itemBool_t)(const void *item);
typedef int8_t (*fn_copyRestrType_t)(const void *peer, const void *item);
typedef bool (*fn_innerCopyRestr_t)(const void *inner, const void *item);
typedef bool (*fn_overlayCanSave_t)(const void *overlay);
typedef bool (*fn_overlayShowRestr_t)(const void *overlay, bool a1);
typedef bool (*fn_peerAllowsFwd_t)(const void *peer);

static fn_sendReadRequests_t   orig_sendReadRequests   = NULL;
static fn_mtpSendRequest_t     orig_mtpSendRequest     = NULL;
static fn_sessionSendPrepared_t orig_sessionSendPrepared = NULL;
static fn_beforeDestroy_t      orig_beforeDestroy      = NULL;
static fn_destroyMessage_t     orig_destroyMessage     = NULL;
static fn_applyEdition_t       orig_applyEdition       = NULL;
static fn_originalText_t       HistoryItem_originalText = NULL;
static fn_setText_t            HistoryItem_setText     = NULL;
static uintptr_t               addr_QString_fromUtf8   = 0;

static fn_itemBool_t           orig_itemAllowsFwd      = NULL;
static fn_itemBool_t           orig_itemAllowsSave     = NULL;
static fn_copyRestrType_t      orig_copyRestrType      = NULL;
static fn_innerCopyRestr_t     orig_innerCopyRestr     = NULL;
static fn_innerCopyRestr_t     orig_innerMediaRestr    = NULL;
static fn_overlayCanSave_t     orig_overlayCanSave     = NULL;
static fn_overlayShowRestr_t   orig_overlayShowRestr   = NULL;
static fn_peerAllowsFwd_t      orig_peerAllowsFwd      = NULL;

static void update_ui_menus(void);

// ============================================================================
// Helper: Construct QString (Qt 6.11 ARM64) from UTF-8 via 0x101bac00c
// ============================================================================

typedef struct {
    void *d;
    const uint16_t *ptr;
    int64_t size;
} TGQString;

typedef struct {
    TGQString text;
    void *ent_d;
    void *ent_ptr;
    int64_t ent_size;
} TGTextWithEntities;

static void tg_qstring_from_utf8(TGQString *out_str, const char *utf8, int64_t len) {
    uintptr_t fn = addr_QString_fromUtf8;
    __asm__ volatile(
        "mov x8, %0\n"
        "mov x0, %1\n"
        "mov x1, %2\n"
        "blr %3\n"
        :
        : "r"(out_str), "r"(utf8), "r"(len), "r"(fn)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
          "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x30",
          "v0", "v1", "v2", "v3", "memory", "cc"
    );
}

static void tg_qstring_release_extra_ref(TGQString *qstr) {
    // Decrement ref_ if > 1 so the owner holds the sole reference
    if (qstr && qstr->d) {
        int32_t *ref_ptr = (int32_t *)qstr->d;
        int32_t cur = __atomic_load_n(ref_ptr, __ATOMIC_RELAXED);
        if (cur > 1) {
            __atomic_fetch_sub(ref_ptr, 1, __ATOMIC_ACQ_REL);
        }
    }
}

// ============================================================================
// Helper: Clear NoForwards bit on PeerData & HistoryItem in memory
// ============================================================================

static void clear_noforwards_on_peer(const void *peer) {
    if (!peer || !g_unlock_restrictions) return;
    uint8_t *p = (uint8_t *)peer;
    uint8_t peer_type = p[0x0e]; // 0 = UserData, 1 = ChatData, 2 = ChannelData
    if (peer_type == 0) {
        if (p[0x21b] & 0x60) p[0x21b] &= ~0x60;
    } else if (peer_type == 1) {
        if (p[0x289] & 0x01) p[0x289] &= ~0x01;
    } else if (peer_type == 2) {
        if (p[0x1ea] & 0x10) p[0x1ea] &= ~0x10;
    }
}

static void clear_noforwards_on_item(const void *item) {
    if (!item || !g_unlock_restrictions) return;
    uint8_t *it = (uint8_t *)item;
    if (it[0x2a] & 0x02) {
        it[0x2a] &= ~0x02; // Clear MessageFlag::NoForwards (bit 17 of _flags)
    }
    void *history = *(void **)(it + 0x10);
    if (history) {
        void *peer = *(void **)((uint8_t *)history + 0x328);
        clear_noforwards_on_peer(peer);
    }
}

// ============================================================================
// Hook 1: Data::Histories::sendReadRequests (0x10573950c)
// ============================================================================

static void hook_sendReadRequests(void *histories) {
    pthread_mutex_lock(&g_lock);
    bool flushing = g_flushing_now;
    pthread_mutex_unlock(&g_lock);

    if (!g_block_read || flushing) {
        orig_sendReadRequests(histories);
        return;
    }

    uint8_t *base = (uint8_t *)histories;
    uint8_t *begin = *(uint8_t **)(base + 0x40);
    uint8_t *end   = *(uint8_t **)(base + 0x48);

    if (!begin || !end || end < begin || (end - begin) > 0x100000) {
        return;
    }

    bool any_suppressed = false;
    for (uint8_t *p = begin; p < end; p += 0x58) {
        void *history = *(void **)(p + 0x00);
        if (history && g_unlock_restrictions) {
            void *peer = *(void **)((uint8_t *)history + 0x328);
            clear_noforwards_on_peer(peer);
        }
        int64_t sent_till = *(int64_t *)(p + 0x30);
        int64_t will_till = *(int64_t *)(p + 0x38);
        if (will_till > sent_till && will_till > 0) {
            pthread_mutex_lock(&g_lock);
            g_last_histories = histories;
            g_last_history = history;
            g_last_read_till = (int32_t)will_till;
            pthread_mutex_unlock(&g_lock);

            *(int64_t *)(p + 0x38) = 0; // willReadTill = 0
            *(int64_t *)(p + 0x40) = 0; // willReadWhen = 0
            any_suppressed = true;
        }
    }

    if (any_suppressed) {
        g_stat_reads++;
        ghost_log("[ReadInbox] Suppressed read receipt (history=%p till=%d, total=%llu)",
                  g_last_history, g_last_read_till, (unsigned long long)g_stat_reads);
        dispatch_async(dispatch_get_main_queue(), ^{
            update_ui_menus();
        });
    }

    orig_sendReadRequests(histories);
}

// ============================================================================
// Shared MTProto Outgoing Filter (MTP::Instance & MTP::details::Session)
// ============================================================================

static bool should_block_tl_constructor(uint32_t cons, void *d_ptr_raw) {
    uint32_t *d_ptr = (uint32_t *)d_ptr_raw;
    if (g_flushing_now) return false;

    if (g_block_read) {
        if (cons == TL_MESSAGES_READ_HISTORY_32 ||
            cons == TL_CHANNELS_READ_HISTORY ||
            cons == TL_MESSAGES_READ_ENCRYPTED_HISTORY ||
            cons == TL_MESSAGES_READ_DISCUSSION ||
            cons == TL_MESSAGES_READ_SAVED_HISTORY ||
            cons == TL_MESSAGES_READ_MENTIONS ||
            cons == TL_MESSAGES_READ_REACTIONS ||
            cons == TL_MESSAGES_READ_POLL_VOTES ||
            cons == TL_MESSAGES_REPORT_READ_METRICS) {
            g_stat_reads++;
            ghost_log("[MTP] BLOCKED ReadReceipt RPC 0x%08x (total=%llu)",
                      cons, (unsigned long long)g_stat_reads);
            dispatch_async(dispatch_get_main_queue(), ^{ update_ui_menus(); });
            return true;
        }
    }

    if (g_block_stories && cons == TL_STORIES_READ_STORIES) {
        g_stat_stories++;
        ghost_log("[MTP] BLOCKED StoryRead RPC 0x%08x (total=%llu)",
                  cons, (unsigned long long)g_stat_stories);
        dispatch_async(dispatch_get_main_queue(), ^{ update_ui_menus(); });
        return true;
    }

    if (g_block_media && (cons == TL_MESSAGES_READ_MESSAGE_CONTENTS ||
                          cons == TL_CHANNELS_READ_MESSAGE_CONTENTS)) {
        g_stat_media++;
        ghost_log("[MTP] BLOCKED MediaContentsRead RPC 0x%08x (total=%llu)",
                  cons, (unsigned long long)g_stat_media);
        dispatch_async(dispatch_get_main_queue(), ^{ update_ui_menus(); });
        return true;
    }

    if (g_block_typing && (cons == TL_MESSAGES_SET_TYPING ||
                           cons == TL_MESSAGES_SET_ENCRYPTED_TYPING)) {
        g_stat_typing++;
        ghost_log("[MTP] BLOCKED SetTyping RPC 0x%08x (total=%llu)",
                  cons, (unsigned long long)g_stat_typing);
        dispatch_async(dispatch_get_main_queue(), ^{ update_ui_menus(); });
        return true;
    }

    if (g_block_screenshot && cons == TL_MESSAGES_SEND_SCREENSHOT_NOTIFY) {
        g_stat_screenshot++;
        ghost_log("[MTP] BLOCKED ScreenshotNotification RPC 0x%08x (total=%llu)",
                  cons, (unsigned long long)g_stat_screenshot);
        dispatch_async(dispatch_get_main_queue(), ^{ update_ui_menus(); });
        return true;
    }

    if (g_hide_online && cons == TL_ACCOUNT_UPDATE_STATUS && d_ptr != NULL) {
        if (d_ptr[9] == TL_BOOL_FALSE) {
            d_ptr[9] = TL_BOOL_TRUE; // Force offline=true
            ghost_log("[MTP] Rewrote account.updateStatus offline=false -> offline=true");
        }
    }

    return false;
}

static uint64_t hook_mtpSendRequest(void *instance, void *serializedReq, void *callbacks,
                                    uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7) {
    if (serializedReq) {
        uint32_t *d_ptr = *((uint32_t **)serializedReq + 1);
        int64_t size = *((int64_t *)serializedReq + 2);
        if (d_ptr && size >= 9) {
            uint32_t cons = d_ptr[8];
            if (should_block_tl_constructor(cons, d_ptr)) {
                return 0;
            }
        }
    }
    return orig_mtpSendRequest(instance, serializedReq, callbacks, a3, a4, a5, a6, a7);
}

static void hook_sessionSendPrepared(void *session, void *prepared, int64_t msCanWait) {
    if (prepared) {
        uint32_t *d_ptr = *((uint32_t **)prepared + 1);
        int64_t size = *((int64_t *)prepared + 2);
        if (d_ptr && size >= 9) {
            uint32_t cons = d_ptr[8];
            if (should_block_tl_constructor(cons, d_ptr)) {
                return;
            }
        }
    }
    orig_sessionSendPrepared(session, prepared, msCanWait);
}

// ============================================================================
// Feature 1: Anti-Delete Hooks (BeforeDestroy & History::destroyMessage)
// ============================================================================

static void hook_beforeDestroy(void *session, void **begin, void **end) {
    if (g_anti_delete) {
        // Skip unloading media or clearing reply references for deleted messages
        return;
    }
    orig_beforeDestroy(session, begin, end);
}

static void hook_antiDelete(void *history, void *item) {
    if (!g_anti_delete || !item) {
        orig_destroyMessage(history, item);
        return;
    }

    @autoreleasepool {
        const TGTextWithEntities *orig = (const TGTextWithEntities *)HistoryItem_originalText(item);
        if (orig) {
            const uint16_t *ptr = orig->text.ptr;
            int64_t len = orig->text.size;

            NSString *currentText = @"";
            if (ptr && len > 0 && len < 65536) {
                currentText = [[NSString alloc] initWithCharacters:ptr length:(NSUInteger)len];
            }

            if (![currentText hasSuffix:@"[🗑️ Silindi]"]) {
                NSString *markedText = (currentText.length > 0)
                    ? [NSString stringWithFormat:@"%@ [🗑️ Silindi]", currentText]
                    : @"[🗑️ Silindi]";
                const char *utf8 = [markedText UTF8String];
                if (utf8) {
                    TGTextWithEntities newTwe;
                    memset(&newTwe, 0, sizeof(newTwe));
                    tg_qstring_from_utf8(&newTwe.text, utf8, (int64_t)strlen(utf8));
                    newTwe.ent_d = orig->ent_d;
                    newTwe.ent_ptr = orig->ent_ptr;
                    newTwe.ent_size = orig->ent_size;

                    HistoryItem_setText(item, &newTwe);
                    tg_qstring_release_extra_ref(&newTwe.text);
                }
            }
        }
    }

    g_stat_deleted++;
    ghost_log("[AntiDelete] Preserved deleted message (item=%p, total=%llu)",
              item, (unsigned long long)g_stat_deleted);
    dispatch_async(dispatch_get_main_queue(), ^{
        update_ui_menus();
    });
}

// ============================================================================
// Feature 2: Anti-Edit Hook (HistoryItem::applyEdition at 0x10690b3b4)
// ============================================================================

static void hook_applyEdition(void *item, void *edition) {
    if (!g_anti_edit || !item || !edition) {
        orig_applyEdition(item, edition);
        return;
    }

    uint8_t *ed_bytes = (uint8_t *)edition;
    TGQString *ed_qstr = (TGQString *)(ed_bytes + 0x48);
    TGQString saved_qstr = *ed_qstr;
    bool replaced = false;
    TGQString custom_qstr = {0, NULL, 0};

    @autoreleasepool {
        const TGTextWithEntities *orig = (const TGTextWithEntities *)HistoryItem_originalText(item);
        if (orig && orig->text.ptr && orig->text.size > 0 && orig->text.size < 32768 &&
            ed_qstr->ptr && ed_qstr->size >= 0 && ed_qstr->size < 32768) {
            NSString *oldStr = [[NSString alloc] initWithCharacters:orig->text.ptr
                                                             length:(NSUInteger)orig->text.size];
            NSString *newStr = (ed_qstr->size > 0)
                ? [[NSString alloc] initWithCharacters:ed_qstr->ptr length:(NSUInteger)ed_qstr->size]
                : @"";

            if (oldStr.length > 0 && ![oldStr isEqualToString:newStr] &&
                ![newStr containsString:@"[✏️ Eski:"]) {
                NSString *combined = [NSString stringWithFormat:@"%@\n[✏️ Eski: %@]", newStr, oldStr];
                const char *utf8 = [combined UTF8String];
                if (utf8) {
                    tg_qstring_from_utf8(&custom_qstr, utf8, (int64_t)strlen(utf8));
                    if (custom_qstr.ptr) {
                        *ed_qstr = custom_qstr;
                        replaced = true;
                    }
                }
            }
        }
    }

    orig_applyEdition(item, edition);

    if (replaced) {
        // Restore edition's original QString so ~HistoryMessageEdition frees it cleanly,
        // and drop our temporary stack reference on custom_qstr so HistoryItem owns it.
        *ed_qstr = saved_qstr;
        tg_qstring_release_extra_ref(&custom_qstr);

        g_stat_edited++;
        ghost_log("[AntiEdit] Preserved edit history on item=%p (total=%llu)",
                  item, (unsigned long long)g_stat_edited);
        dispatch_async(dispatch_get_main_queue(), ^{
            update_ui_menus();
        });
    }
}

// ============================================================================
// Feature 3 & 5: TTL Media Bypass & NoForwards / Copy / Save Unlock Hooks
// ============================================================================

static int64_t hook_mediaTtlSeconds(const void *media) {
    if (!media) return 0;
    if (g_bypass_ttl || g_unlock_restrictions) {
        return 0;
    }
    return *(const int64_t *)((const uint8_t *)media + 0x20);
}

static bool hook_itemAllowsFwd(const void *item) {
    if (g_unlock_restrictions) {
        clear_noforwards_on_item(item);
        return true;
    }
    return orig_itemAllowsFwd(item);
}

static bool hook_itemAllowsSave(const void *item) {
    if (g_unlock_restrictions) {
        clear_noforwards_on_item(item);
        return true;
    }
    return orig_itemAllowsSave(item);
}

static int8_t hook_copyRestrType(const void *peer, const void *item) {
    if (g_unlock_restrictions) {
        clear_noforwards_on_peer(peer);
        clear_noforwards_on_item(item);
        return 0; // CopyRestrictionType::None
    }
    return orig_copyRestrType(peer, item);
}

static bool hook_innerCopyRestr(const void *inner, const void *item) {
    if (g_unlock_restrictions) {
        if (inner) {
            void *peer = *(void **)((const uint8_t *)inner + 0xd8);
            clear_noforwards_on_peer(peer);
        }
        clear_noforwards_on_item(item);
        return false;
    }
    return orig_innerCopyRestr(inner, item);
}

static bool hook_innerMediaRestr(const void *peer, const void *item) {
    if (g_unlock_restrictions) {
        clear_noforwards_on_peer(peer);
        clear_noforwards_on_item(item);
        return false;
    }
    return orig_innerMediaRestr(peer, item);
}

static bool hook_overlayCanSave(const void *overlay) {
    if (g_unlock_restrictions && overlay) {
        void *history = *(void **)((const uint8_t *)overlay + 0xd68);
        if (history) {
            void *peer = *(void **)((const uint8_t *)history + 0x328);
            clear_noforwards_on_peer(peer);
        }
        void *item = *(void **)((const uint8_t *)overlay + 0xe40);
        clear_noforwards_on_item(item);
        return true;
    }
    return orig_overlayCanSave(overlay);
}

static bool hook_overlayShowRestr(const void *overlay, bool a1) {
    if (g_unlock_restrictions) {
        if (overlay) {
            void *history = *(void **)((const uint8_t *)overlay + 0xd68);
            if (history) {
                void *peer = *(void **)((const uint8_t *)history + 0x328);
                clear_noforwards_on_peer(peer);
            }
            void *item = *(void **)((const uint8_t *)overlay + 0xe40);
            clear_noforwards_on_item(item);
        }
        return false; // false = no restriction shown
    }
    return orig_overlayShowRestr(overlay, a1);
}

static bool hook_peerAllowsFwd(const void *peer) {
    if (g_unlock_restrictions) {
        clear_noforwards_on_peer(peer);
        return true;
    }
    return orig_peerAllowsFwd(peer);
}

// ============================================================================
// Cocoa UI: Floating In-Window Button, Dark HUD Control Panel & Menu Bar
// ============================================================================

@interface TGGhostMenuController : NSObject
@property (strong, nonatomic) NSStatusItem *statusItem;
@property (strong, nonatomic) NSMenu *ghostMenu;
@property (strong, nonatomic) NSMenuItem *appBarRootItem;
@property (strong, nonatomic) NSPanel *hudPanel;
@property (strong, nonatomic) NSButton *windowBadgeButton;
@property (strong, nonatomic) NSSwitch *swRead;
@property (strong, nonatomic) NSSwitch *swStories;
@property (strong, nonatomic) NSSwitch *swMedia;
@property (strong, nonatomic) NSSwitch *swTyping;
@property (strong, nonatomic) NSSwitch *swOnline;
@property (strong, nonatomic) NSSwitch *swAntiDelete;
@property (strong, nonatomic) NSSwitch *swAntiEdit;
@property (strong, nonatomic) NSSwitch *swUnlock;
@property (strong, nonatomic) NSSwitch *swScreenshot;
@property (strong, nonatomic) NSSwitch *swBypassTTL;
@property (strong, nonatomic) NSTextField *lblStats;
- (void)setupMenus;
- (void)refreshState;
- (void)attachInWindowBadgeIfNeeded;
@end

static TGGhostMenuController *g_menuController = nil;

@implementation TGGhostMenuController

- (NSMenu *)buildMenu {
    NSMenu *menu = [[NSMenu alloc] initWithTitle:@"Hayalet Mod"];
    [menu setAutoenablesItems:NO];

    NSMenuItem *header = [[NSMenuItem alloc] initWithTitle:@"👻 Telegram Hayalet Mod v2.0"
                                                    action:nil
                                             keyEquivalent:@""];
    [header setEnabled:NO];
    [menu addItem:header];

    NSMenuItem *openHud = [[NSMenuItem alloc] initWithTitle:@"🎛️ Kontrol Panelini Aç..."
                                                     action:@selector(showHudPanel:)
                                              keyEquivalent:@"g"];
    [openHud setKeyEquivalentModifierMask:(NSEventModifierFlagCommand | NSEventModifierFlagOption)];
    [openHud setTarget:self];
    [menu addItem:openHud];

    [menu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *itemRead = [[NSMenuItem alloc] initWithTitle:@"Mesaj Görüldüsü Kapat (Çift Tik Engelle)"
                                                      action:@selector(toggleBlockRead:)
                                               keyEquivalent:@"G"];
    [itemRead setKeyEquivalentModifierMask:(NSEventModifierFlagCommand | NSEventModifierFlagShift)];
    [itemRead setTarget:self];
    [itemRead setTag:101];
    [menu addItem:itemRead];

    NSMenuItem *itemStories = [[NSMenuItem alloc] initWithTitle:@"Hikaye (Story) Görüldüsü Kapat"
                                                         action:@selector(toggleBlockStories:)
                                                  keyEquivalent:@""];
    [itemStories setTarget:self];
    [itemStories setTag:102];
    [menu addItem:itemStories];

    NSMenuItem *itemMedia = [[NSMenuItem alloc] initWithTitle:@"Sesli Mesaj / Medya Açıldı Bilgisi Kapat"
                                                       action:@selector(toggleBlockMedia:)
                                                keyEquivalent:@""];
    [itemMedia setTarget:self];
    [itemMedia setTag:103];
    [menu addItem:itemMedia];

    NSMenuItem *itemTyping = [[NSMenuItem alloc] initWithTitle:@"Yazıyor... / Kaydediyor... Gizle"
                                                        action:@selector(toggleBlockTyping:)
                                                 keyEquivalent:@"T"];
    [itemTyping setKeyEquivalentModifierMask:(NSEventModifierFlagCommand | NSEventModifierFlagShift)];
    [itemTyping setTarget:self];
    [itemTyping setTag:104];
    [menu addItem:itemTyping];

    NSMenuItem *itemOnline = [[NSMenuItem alloc] initWithTitle:@"Çevrimiçi (Online) Durumunu Gizle"
                                                        action:@selector(toggleHideOnline:)
                                                 keyEquivalent:@""];
    [itemOnline setTarget:self];
    [itemOnline setTag:105];
    [menu addItem:itemOnline];

    [menu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *itemAntiDel = [[NSMenuItem alloc] initWithTitle:@"🗑️ Silinen Mesajları Yakala (Anti-Delete)"
                                                         action:@selector(toggleAntiDelete:)
                                                  keyEquivalent:@""];
    [itemAntiDel setTarget:self];
    [itemAntiDel setTag:106];
    [menu addItem:itemAntiDel];

    NSMenuItem *itemAntiEdit = [[NSMenuItem alloc] initWithTitle:@"✏️ Düzenlenen Mesaj Geçmişi (Anti-Edit)"
                                                          action:@selector(toggleAntiEdit:)
                                                   keyEquivalent:@""];
    [itemAntiEdit setTarget:self];
    [itemAntiEdit setTag:107];
    [menu addItem:itemAntiEdit];

    NSMenuItem *itemUnlock = [[NSMenuItem alloc] initWithTitle:@"🔓 Kopyalama / İndirme Kilidi Aç (NoForwards)"
                                                        action:@selector(toggleUnlockRestrictions:)
                                                 keyEquivalent:@""];
    [itemUnlock setTarget:self];
    [itemUnlock setTag:108];
    [menu addItem:itemUnlock];

    NSMenuItem *itemShot = [[NSMenuItem alloc] initWithTitle:@"📸 Ekran Görüntüsü Bildirimi Engelle"
                                                      action:@selector(toggleBlockScreenshot:)
                                               keyEquivalent:@""];
    [itemShot setTarget:self];
    [itemShot setTag:109];
    [menu addItem:itemShot];

    NSMenuItem *itemTtl = [[NSMenuItem alloc] initWithTitle:@"⏱️ Tek Gösterimlik / Süreli Medya Kaydet (TTL)"
                                                     action:@selector(toggleBypassTTL:)
                                              keyEquivalent:@""];
    [itemTtl setTarget:self];
    [itemTtl setTag:110];
    [menu addItem:itemTtl];

    [menu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *itemFlush = [[NSMenuItem alloc] initWithTitle:@"✓ Son Açılan Sohbete Şimdi Görüldü Gönder"
                                                       action:@selector(flushLastHistoryRead:)
                                                keyEquivalent:@"R"];
    [itemFlush setKeyEquivalentModifierMask:(NSEventModifierFlagCommand | NSEventModifierFlagShift)];
    [itemFlush setTarget:self];
    [itemFlush setTag:200];
    [menu addItem:itemFlush];

    [menu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *itemStats = [[NSMenuItem alloc] initWithTitle:@"İstatistik: Görüldü 0 | Silinen 0 | Düzenlenen 0"
                                                       action:nil
                                                keyEquivalent:@""];
    [itemStats setEnabled:NO];
    [itemStats setTag:300];
    [menu addItem:itemStats];

    return menu;
}

- (NSSwitch *)addSwitchRowToView:(NSView *)parent
                           title:(NSString *)title
                        subtitle:(NSString *)subtitle
                            yPos:(CGFloat)yPos
                          action:(SEL)action {
    NSTextField *lblTitle = [NSTextField labelWithString:title];
    lblTitle.font = [NSFont systemFontOfSize:12.5 weight:NSFontWeightSemibold];
    lblTitle.textColor = [NSColor whiteColor];
    lblTitle.frame = NSMakeRect(18, yPos + 14, 285, 17);
    [parent addSubview:lblTitle];

    NSTextField *lblSub = [NSTextField labelWithString:subtitle];
    lblSub.font = [NSFont systemFontOfSize:10.5 weight:NSFontWeightRegular];
    lblSub.textColor = [NSColor colorWithWhite:0.68 alpha:1.0];
    lblSub.frame = NSMakeRect(18, yPos - 1, 285, 14);
    [parent addSubview:lblSub];

    NSSwitch *sw = [[NSSwitch alloc] initWithFrame:NSMakeRect(315, yPos + 3, 44, 24)];
    sw.target = self;
    sw.action = action;
    [parent addSubview:sw];
    return sw;
}

- (void)buildHudPanelIfNeeded {
    if (self.hudPanel) return;

    NSRect rect = NSMakeRect(0, 0, 380, 610);
    NSPanel *panel = [[NSPanel alloc] initWithContentRect:rect
                                                styleMask:(NSWindowStyleMaskTitled |
                                                           NSWindowStyleMaskClosable |
                                                           NSWindowStyleMaskUtilityWindow |
                                                           NSWindowStyleMaskFullSizeContentView)
                                                  backing:NSBackingStoreBuffered
                                                    defer:NO];
    panel.title = @"Telegram Hayalet Mod v2.0";
    panel.titlebarAppearsTransparent = YES;
    panel.floatingPanel = YES;
    panel.level = NSFloatingWindowLevel;
    panel.appearance = [NSAppearance appearanceNamed:NSAppearanceNameVibrantDark];
    panel.releasedWhenClosed = NO;

    NSVisualEffectView *bg = [[NSVisualEffectView alloc] initWithFrame:rect];
    bg.material = NSVisualEffectMaterialHUDWindow;
    bg.blendingMode = NSVisualEffectBlendingModeBehindWindow;
    bg.state = NSVisualEffectStateActive;
    panel.contentView = bg;

    NSTextField *header = [NSTextField labelWithString:@"👻 Hayalet Mod v2.0"];
    header.font = [NSFont boldSystemFontOfSize:16];
    header.textColor = [NSColor whiteColor];
    header.frame = NSMakeRect(18, 566, 340, 22);
    [bg addSubview:header];

    // Section 1: Ghost & Privacy
    NSTextField *sec1 = [NSTextField labelWithString:@"GİZLİLİK & GÖRÜLDÜ KORUMASI"];
    sec1.font = [NSFont systemFontOfSize:10 weight:NSFontWeightBold];
    sec1.textColor = [NSColor colorWithRed:0.35 green:0.78 blue:1.0 alpha:1.0];
    sec1.frame = NSMakeRect(18, 544, 340, 14);
    [bg addSubview:sec1];

    self.swRead = [self addSwitchRowToView:bg
                                     title:@"Mesaj Görüldüsü Kapat"
                                  subtitle:@"Sohbetleri okusan da karşıya çift tik gitmez (⌘⇧G)"
                                      yPos:504
                                    action:@selector(toggleBlockRead:)];

    self.swStories = [self addSwitchRowToView:bg
                                        title:@"Hikaye (Story) Görüldüsü Kapat"
                                     subtitle:@"Baktığın hikayelerde izleyenler listesinde görünmezsin"
                                         yPos:464
                                       action:@selector(toggleBlockStories:)];

    self.swMedia = [self addSwitchRowToView:bg
                                      title:@"Sesli Mesaj / Medya Açıldı Kapat"
                                   subtitle:@"Sesli mesajları dinlediğinde karşıda 'dinlendi' olmaz"
                                       yPos:424
                                     action:@selector(toggleBlockMedia:)];

    self.swTyping = [self addSwitchRowToView:bg
                                       title:@"Yazıyor... / Kaydediyor... Gizle"
                                    subtitle:@"Mesaj yazarken veya ses kaydederken durum gitmez (⌘⇧T)"
                                        yPos:384
                                      action:@selector(toggleBlockTyping:)];

    self.swOnline = [self addSwitchRowToView:bg
                                       title:@"Çevrimiçi (Online) Durumunu Gizle"
                                    subtitle:@"Telegram açıkken sunucuya 'offline' durumu bildirir"
                                        yPos:344
                                      action:@selector(toggleHideOnline:)];

    NSBox *sep1 = [[NSBox alloc] initWithFrame:NSMakeRect(18, 332, 344, 1)];
    sep1.boxType = NSBoxSeparator;
    [bg addSubview:sep1];

    // Section 2: v2.0 Protection & Unlocks
    NSTextField *sec2 = [NSTextField labelWithString:@"MESAJ & MEDYA KORUMASI (v2.0)"];
    sec2.font = [NSFont systemFontOfSize:10 weight:NSFontWeightBold];
    sec2.textColor = [NSColor colorWithRed:0.30 green:0.90 blue:0.55 alpha:1.0];
    sec2.frame = NSMakeRect(18, 312, 340, 14);
    [bg addSubview:sec2];

    self.swAntiDelete = [self addSwitchRowToView:bg
                                           title:@"🗑️ Silinen Mesajları Yakala (Anti-Delete)"
                                        subtitle:@"Karşı taraf silse bile mesaj kalır, [🗑️ Silindi] yazılır"
                                            yPos:272
                                          action:@selector(toggleAntiDelete:)];

    self.swAntiEdit = [self addSwitchRowToView:bg
                                         title:@"✏️ Düzenlenen Mesaj Geçmişi (Anti-Edit)"
                                      subtitle:@"Mesaj düzenlendiğinde altında [✏️ Eski: ...] gösterilir"
                                          yPos:232
                                        action:@selector(toggleAntiEdit:)];

    self.swUnlock = [self addSwitchRowToView:bg
                                       title:@"🔓 Kopyalama / İndirme Kilidi Aç"
                                    subtitle:@"Korumalı kanal ve sohbetlerde kopyalama/kaydetmeyi açar"
                                        yPos:192
                                      action:@selector(toggleUnlockRestrictions:)];

    self.swScreenshot = [self addSwitchRowToView:bg
                                           title:@"📸 Ekran Görüntüsü Bildirimi Engelle"
                                        subtitle:@"SS alındığında karşıya bildirim gitmesini engeller"
                                            yPos:152
                                          action:@selector(toggleBlockScreenshot:)];

    self.swBypassTTL = [self addSwitchRowToView:bg
                                          title:@"⏱️ Tek Gösterimlik / Süreli Medya Kaydet"
                                       subtitle:@"Süreli (TTL) foto/videoları normal medya gibi açar ve kaydeder"
                                           yPos:112
                                         action:@selector(toggleBypassTTL:)];

    NSButton *btnFlush = [NSButton buttonWithTitle:@"✓ Son Açılan Sohbete Şimdi Görüldü Gönder (⌘⇧R)"
                                            target:self
                                            action:@selector(flushLastHistoryRead:)];
    btnFlush.bezelStyle = NSBezelStyleRounded;
    btnFlush.frame = NSMakeRect(18, 62, 344, 30);
    [bg addSubview:btnFlush];

    NSTextField *stats = [NSTextField labelWithString:@"Görüldü: 0 | Silinen: 0 | Düzenlenen: 0 | SS: 0"];
    stats.font = [NSFont monospacedDigitSystemFontOfSize:11 weight:NSFontWeightMedium];
    stats.textColor = [NSColor colorWithRed:0.35 green:0.85 blue:0.55 alpha:1.0];
    stats.alignment = NSTextAlignmentCenter;
    stats.frame = NSMakeRect(14, 18, 352, 32);
    [bg addSubview:stats];
    self.lblStats = stats;

    self.hudPanel = panel;
}

- (void)attachInWindowBadgeIfNeeded {
    NSWindow *mainWin = [NSApp mainWindow];
    if (!mainWin) {
        for (NSWindow *w in [NSApp windows]) {
            if ([w isVisible] && w. frame.size.width > 300 && w != self.hudPanel) {
                mainWin = w;
                break;
            }
        }
    }
    if (!mainWin || !mainWin.contentView) return;

    NSView *themeFrame = mainWin.contentView.superview;
    if (!themeFrame) return;

    if (!self.windowBadgeButton) {
        NSButton *btn = [[NSButton alloc] initWithFrame:NSMakeRect(themeFrame.bounds.size.width - 134,
                                                                   themeFrame.bounds.size.height - 32,
                                                                   122, 24)];
        btn.bezelStyle = NSBezelStyleAccessoryBarAction;
        btn.wantsLayer = YES;
        btn.layer.cornerRadius = 11.0;
        btn.layer.backgroundColor = [NSColor colorWithRed:0.12 green:0.14 blue:0.18 alpha:0.90].CGColor;
        btn.font = [NSFont systemFontOfSize:11.5 weight:NSFontWeightSemibold];
        btn.target = self;
        btn.action = @selector(showHudPanel:);
        btn.toolTip = @"Telegram Hayalet Mod v2.0 (Tıkla)";
        btn.autoresizingMask = (NSViewMinXMargin | NSViewMinYMargin);
        self.windowBadgeButton = btn;
    }

    if (self.windowBadgeButton.superview != themeFrame) {
        [self.windowBadgeButton removeFromSuperview];
        self.windowBadgeButton.frame = NSMakeRect(themeFrame.bounds.size.width - 134,
                                                  themeFrame.bounds.size.height - 32,
                                                  122, 24);
        [themeFrame addSubview:self.windowBadgeButton positioned:NSWindowAbove relativeTo:nil];
        ghost_log("[UI] Attached in-window Ghost button to Telegram window (%p)", mainWin);
    }
}

- (void)showHudPanel:(id)sender {
    [self buildHudPanelIfNeeded];
    [self attachInWindowBadgeIfNeeded];
    [self refreshState];
    if ([self.hudPanel isVisible]) {
        [self.hudPanel orderOut:nil];
    } else {
        NSWindow *mainWin = [NSApp mainWindow] ?: [[NSApp windows] firstObject];
        if (mainWin && mainWin != self.hudPanel) {
            NSRect wf = mainWin.frame;
            NSRect pf = self.hudPanel.frame;
            NSPoint pt = NSMakePoint(NSMaxX(wf) - pf.size.width - 20,
                                     NSMaxY(wf) - pf.size.height - 44);
            [self.hudPanel setFrameOrigin:pt];
        } else {
            [self.hudPanel center];
        }
        [self.hudPanel makeKeyAndOrderFront:nil];
        [NSApp activateIgnoringOtherApps:YES];
    }
}

- (void)setupMenus {
    if (!self.statusItem) {
        self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
        self.ghostMenu = [self buildMenu];
        self.statusItem.menu = self.ghostMenu;
    }

    NSMenu *mainMenu = [NSApp mainMenu];
    if (mainMenu && [mainMenu indexOfItemWithTitle:@"Hayalet Mod"] == -1) {
        self.appBarRootItem = [[NSMenuItem alloc] initWithTitle:@"Hayalet Mod"
                                                         action:nil
                                                  keyEquivalent:@""];
        NSMenu *subMenu = [self buildMenu];
        [self.appBarRootItem setSubmenu:subMenu];
        [mainMenu addItem:self.appBarRootItem];
    }

    [self attachInWindowBadgeIfNeeded];
    [self refreshState];
}

- (void)updateMenuInstance:(NSMenu *)menu {
    if (!menu) return;
    [[menu itemWithTag:101] setState:(g_block_read ? NSControlStateValueOn : NSControlStateValueOff)];
    [[menu itemWithTag:102] setState:(g_block_stories ? NSControlStateValueOn : NSControlStateValueOff)];
    [[menu itemWithTag:103] setState:(g_block_media ? NSControlStateValueOn : NSControlStateValueOff)];
    [[menu itemWithTag:104] setState:(g_block_typing ? NSControlStateValueOn : NSControlStateValueOff)];
    [[menu itemWithTag:105] setState:(g_hide_online ? NSControlStateValueOn : NSControlStateValueOff)];
    [[menu itemWithTag:106] setState:(g_anti_delete ? NSControlStateValueOn : NSControlStateValueOff)];
    [[menu itemWithTag:107] setState:(g_anti_edit ? NSControlStateValueOn : NSControlStateValueOff)];
    [[menu itemWithTag:108] setState:(g_unlock_restrictions ? NSControlStateValueOn : NSControlStateValueOff)];
    [[menu itemWithTag:109] setState:(g_block_screenshot ? NSControlStateValueOn : NSControlStateValueOff)];
    [[menu itemWithTag:110] setState:(g_bypass_ttl ? NSControlStateValueOn : NSControlStateValueOff)];

    NSMenuItem *statsItem = [menu itemWithTag:300];
    if (statsItem) {
        NSString *s = [NSString stringWithFormat:@"Görüldü: %llu | Silinen: %llu | Düzenlenen: %llu | SS: %llu",
                       (unsigned long long)g_stat_reads,
                       (unsigned long long)g_stat_deleted,
                       (unsigned long long)g_stat_edited,
                       (unsigned long long)g_stat_screenshot];
        [statsItem setTitle:s];
    }
}

- (void)refreshState {
    if (self.statusItem.button) {
        self.statusItem.button.title = g_block_read ? @"👻 TG" : @"👁️ TG";
    }
    if (self.windowBadgeButton) {
        self.windowBadgeButton.title = g_block_read ? @"👻 Hayalet: AÇIK" : @"👁️ Hayalet: KAPALI";
        self.windowBadgeButton.contentTintColor = g_block_read
            ? [NSColor colorWithRed:0.35 green:0.92 blue:0.55 alpha:1.0]
            : [NSColor colorWithWhite:0.85 alpha:1.0];
    }
    if (self.swRead)       self.swRead.state       = g_block_read          ? NSControlStateValueOn : NSControlStateValueOff;
    if (self.swStories)    self.swStories.state    = g_block_stories       ? NSControlStateValueOn : NSControlStateValueOff;
    if (self.swMedia)      self.swMedia.state      = g_block_media         ? NSControlStateValueOn : NSControlStateValueOff;
    if (self.swTyping)     self.swTyping.state     = g_block_typing        ? NSControlStateValueOn : NSControlStateValueOff;
    if (self.swOnline)     self.swOnline.state     = g_hide_online         ? NSControlStateValueOn : NSControlStateValueOff;
    if (self.swAntiDelete) self.swAntiDelete.state = g_anti_delete         ? NSControlStateValueOn : NSControlStateValueOff;
    if (self.swAntiEdit)   self.swAntiEdit.state   = g_anti_edit           ? NSControlStateValueOn : NSControlStateValueOff;
    if (self.swUnlock)     self.swUnlock.state     = g_unlock_restrictions ? NSControlStateValueOn : NSControlStateValueOff;
    if (self.swScreenshot) self.swScreenshot.state = g_block_screenshot    ? NSControlStateValueOn : NSControlStateValueOff;
    if (self.swBypassTTL)  self.swBypassTTL.state  = g_bypass_ttl          ? NSControlStateValueOn : NSControlStateValueOff;

    if (self.lblStats) {
        self.lblStats.stringValue = [NSString stringWithFormat:
            @"Görüldü: %llu | Silinen: %llu | Düzenlenen: %llu\nStory: %llu | Yazıyor: %llu | SS: %llu",
            (unsigned long long)g_stat_reads,
            (unsigned long long)g_stat_deleted,
            (unsigned long long)g_stat_edited,
            (unsigned long long)g_stat_stories,
            (unsigned long long)g_stat_typing,
            (unsigned long long)g_stat_screenshot];
    }
    [self updateMenuInstance:self.statusItem.menu];
    if (self.appBarRootItem.submenu) {
        [self updateMenuInstance:self.appBarRootItem.submenu];
    }
}

- (void)toggleBlockRead:(id)sender {
    g_block_read = !g_block_read;
    save_preferences();
    ghost_log("[UI] Toggled g_block_read = %d", (int)g_block_read);
    [self refreshState];
}

- (void)toggleBlockStories:(id)sender {
    g_block_stories = !g_block_stories;
    save_preferences();
    ghost_log("[UI] Toggled g_block_stories = %d", (int)g_block_stories);
    [self refreshState];
}

- (void)toggleBlockMedia:(id)sender {
    g_block_media = !g_block_media;
    save_preferences();
    ghost_log("[UI] Toggled g_block_media = %d", (int)g_block_media);
    [self refreshState];
}

- (void)toggleBlockTyping:(id)sender {
    g_block_typing = !g_block_typing;
    save_preferences();
    ghost_log("[UI] Toggled g_block_typing = %d", (int)g_block_typing);
    [self refreshState];
}

- (void)toggleHideOnline:(id)sender {
    g_hide_online = !g_hide_online;
    save_preferences();
    ghost_log("[UI] Toggled g_hide_online = %d", (int)g_hide_online);
    [self refreshState];
}

- (void)toggleAntiDelete:(id)sender {
    g_anti_delete = !g_anti_delete;
    save_preferences();
    ghost_log("[UI] Toggled g_anti_delete = %d", (int)g_anti_delete);
    [self refreshState];
}

- (void)toggleAntiEdit:(id)sender {
    g_anti_edit = !g_anti_edit;
    save_preferences();
    ghost_log("[UI] Toggled g_anti_edit = %d", (int)g_anti_edit);
    [self refreshState];
}

- (void)toggleUnlockRestrictions:(id)sender {
    g_unlock_restrictions = !g_unlock_restrictions;
    save_preferences();
    ghost_log("[UI] Toggled g_unlock_restrictions = %d", (int)g_unlock_restrictions);
    [self refreshState];
}

- (void)toggleBlockScreenshot:(id)sender {
    g_block_screenshot = !g_block_screenshot;
    save_preferences();
    ghost_log("[UI] Toggled g_block_screenshot = %d", (int)g_block_screenshot);
    [self refreshState];
}

- (void)toggleBypassTTL:(id)sender {
    g_bypass_ttl = !g_bypass_ttl;
    save_preferences();
    ghost_log("[UI] Toggled g_bypass_ttl = %d", (int)g_bypass_ttl);
    [self refreshState];
}

- (void)flushLastHistoryRead:(id)sender {
    pthread_mutex_lock(&g_lock);
    void *histories = g_last_histories;
    void *target_history = g_last_history;
    int32_t target_till = g_last_read_till;
    pthread_mutex_unlock(&g_lock);

    if (!histories || !target_history || target_till <= 0) {
        ghost_log("[UI] Flush requested, but no pending history read receipt found");
        return;
    }

    uint8_t *base = (uint8_t *)histories;
    uint8_t *begin = *(uint8_t **)(base + 0x40);
    uint8_t *end   = *(uint8_t **)(base + 0x48);
    if (!begin || !end || end < begin) return;

    bool found = false;
    for (uint8_t *p = begin; p < end; p += 0x58) {
        if (*(void **)(p + 0x00) == target_history) {
            int64_t sent = *(int64_t *)(p + 0x30);
            if (target_till > sent) {
                *(int64_t *)(p + 0x38) = target_till;
                *(int64_t *)(p + 0x40) = 0;
                found = true;
            }
            break;
        }
    }

    if (found) {
        pthread_mutex_lock(&g_lock);
        g_flushing_now = true;
        pthread_mutex_unlock(&g_lock);

        ghost_log("[UI] Flushing read receipt for last history %p till %d", target_history, target_till);
        orig_sendReadRequests(histories);

        pthread_mutex_lock(&g_lock);
        g_flushing_now = false;
        pthread_mutex_unlock(&g_lock);
    }
    [self refreshState];
}

@end

static void update_ui_menus(void) {
    if (g_menuController) {
        [g_menuController refreshState];
    }
}

static void ensure_ui_setup_on_main(void) {
    if (!g_menuController) {
        g_menuController = [[TGGhostMenuController alloc] init];
    }
    [g_menuController setupMenus];
}

static void *ui_watchdog_thread(void *arg) {
    (void)arg;
    for (int i = 0; i < 30; i++) {
        usleep(500000);
        CFRunLoopRef mainLoop = CFRunLoopGetMain();
        if (mainLoop) {
            CFRunLoopPerformBlock(mainLoop, kCFRunLoopCommonModes, ^{
                ensure_ui_setup_on_main();
            });
            CFRunLoopWakeUp(mainLoop);
        }
    }
    return NULL;
}

// ============================================================================
// Constructor: Install All 15 Hook Slots & Schedule UI Setup
// ============================================================================

__attribute__((constructor))
static void tg_ghost_init(void) {
    load_preferences();

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (hdr && hdr->filetype == MH_EXECUTE) {
            g_aslr_slide = _dyld_get_image_vmaddr_slide(i);
            break;
        }
    }

    // Bind original function pointers via the __TEXT stub + 0x10 trampolines
    orig_sendReadRequests    = (fn_sendReadRequests_t)(g_aslr_slide + STUB_SEND_READ_REQUESTS + 0x10);
    orig_mtpSendRequest      = (fn_mtpSendRequest_t)(g_aslr_slide + STUB_MTP_SEND_REQUEST + 0x10);
    orig_sessionSendPrepared = (fn_sessionSendPrepared_t)(g_aslr_slide + STUB_SESSION_SEND_PREPARED + 0x10);
    orig_beforeDestroy       = (fn_beforeDestroy_t)(g_aslr_slide + VA_BEFORE_DESTROY);
    orig_destroyMessage      = (fn_destroyMessage_t)(g_aslr_slide + VA_DESTROY_MESSAGE);
    orig_applyEdition        = (fn_applyEdition_t)(g_aslr_slide + STUB_APPLY_EDITION + 0x10);

    HistoryItem_originalText = (fn_originalText_t)(g_aslr_slide + VA_ITEM_ORIGINAL_TEXT);
    HistoryItem_setText      = (fn_setText_t)(g_aslr_slide + VA_ITEM_SET_TEXT);
    addr_QString_fromUtf8    = (uintptr_t)(g_aslr_slide + VA_QSTRING_FROM_UTF8);

    orig_itemAllowsFwd       = (fn_itemBool_t)(g_aslr_slide + STUB_ITEM_ALLOWS_FWD + 0x10);
    orig_itemAllowsSave      = (fn_itemBool_t)(g_aslr_slide + STUB_ITEM_ALLOWS_SAVE + 0x10);
    orig_copyRestrType       = (fn_copyRestrType_t)(g_aslr_slide + STUB_COPY_RESTR_TYPE + 0x10);
    orig_innerCopyRestr      = (fn_innerCopyRestr_t)(g_aslr_slide + STUB_INNER_COPY_RESTR + 0x10);
    orig_innerMediaRestr     = (fn_innerCopyRestr_t)(g_aslr_slide + STUB_INNER_MEDIA_RESTR + 0x10);
    orig_overlayCanSave      = (fn_overlayCanSave_t)(g_aslr_slide + STUB_OVERLAY_CAN_SAVE + 0x10);
    orig_overlayShowRestr    = (fn_overlayShowRestr_t)(g_aslr_slide + STUB_OVERLAY_SHOW_RESTR + 0x10);
    orig_peerAllowsFwd       = (fn_peerAllowsFwd_t)(g_aslr_slide + STUB_PEER_ALLOWS_FWD + 0x10);

    // Populate writable __DATA hook pointer table
    *(void **)(g_aslr_slide + SLOT_SEND_READ_REQUESTS)    = (void *)&hook_sendReadRequests;
    *(void **)(g_aslr_slide + SLOT_MTP_SEND_REQUEST)      = (void *)&hook_mtpSendRequest;
    *(void **)(g_aslr_slide + SLOT_SESSION_SEND_PREPARED) = (void *)&hook_sessionSendPrepared;
    *(void **)(g_aslr_slide + SLOT_BEFORE_DESTROY)        = (void *)&hook_beforeDestroy;
    *(void **)(g_aslr_slide + SLOT_ANTI_DELETE)           = (void *)&hook_antiDelete;
    *(void **)(g_aslr_slide + SLOT_APPLY_EDITION)         = (void *)&hook_applyEdition;
    *(void **)(g_aslr_slide + SLOT_MEDIA_TTL)             = (void *)&hook_mediaTtlSeconds;
    *(void **)(g_aslr_slide + SLOT_ITEM_ALLOWS_FWD)       = (void *)&hook_itemAllowsFwd;
    *(void **)(g_aslr_slide + SLOT_ITEM_ALLOWS_SAVE)      = (void *)&hook_itemAllowsSave;
    *(void **)(g_aslr_slide + SLOT_COPY_RESTR_TYPE)       = (void *)&hook_copyRestrType;
    *(void **)(g_aslr_slide + SLOT_INNER_COPY_RESTR)      = (void *)&hook_innerCopyRestr;
    *(void **)(g_aslr_slide + SLOT_INNER_MEDIA_RESTR)     = (void *)&hook_innerMediaRestr;
    *(void **)(g_aslr_slide + SLOT_OVERLAY_CAN_SAVE)      = (void *)&hook_overlayCanSave;
    *(void **)(g_aslr_slide + SLOT_OVERLAY_SHOW_RESTR)    = (void *)&hook_overlayShowRestr;
    *(void **)(g_aslr_slide + SLOT_PEER_ALLOWS_FWD)       = (void *)&hook_peerAllowsFwd;

    ghost_log("Telegram Ghost Plugin v2.0 loaded! slide=0x%lx read=%d del=%d edit=%d unlock=%d shot=%d ttl=%d",
              (unsigned long)g_aslr_slide, (int)g_block_read, (int)g_anti_delete,
              (int)g_anti_edit, (int)g_unlock_restrictions, (int)g_block_screenshot, (int)g_bypass_ttl);

    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    [nc addObserverForName:NSWindowDidBecomeKeyNotification
                    object:nil
                     queue:[NSOperationQueue mainQueue]
                usingBlock:^(NSNotification * _Nonnull note) {
        (void)note;
        ensure_ui_setup_on_main();
    }];

    pthread_t tid;
    pthread_create(&tid, NULL, ui_watchdog_thread, NULL);
    pthread_detach(tid);
}
