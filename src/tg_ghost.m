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
// Telegram Desktop 7.3.3 (arm64 macOS) Virtual Addresses (unslid base 0x100000000)
// ============================================================================
#define VA_CAVE_ORIG_SEND_READ_REQ    0x100011210ULL
#define VA_CAVE_ORIG_MTP_SEND_REQ     0x100011230ULL
#define VA_CAVE_ORIG_SESSION_SEND     0x100011250ULL

#define VA_PTR_HOOK_SEND_READ_REQ     0x10f9c3f00ULL
#define VA_PTR_HOOK_MTP_SEND_REQ      0x10f9c3f08ULL
#define VA_PTR_HOOK_SESSION_SEND      0x10f9c3f10ULL

// ============================================================================
// MTProto TL Constructor IDs (extracted from scheme.cpp)
// ============================================================================
#define MTPC_messages_readHistory          0x0e306d3aU
#define MTPC_channels_readHistory          0xcc104937U
#define MTPC_messages_readEncryptedHistory 0x7f4b690aU
#define MTPC_messages_readDiscussion       0xf731a9f4U
#define MTPC_messages_readSavedHistory     0xba4a3b5bU
#define MTPC_messages_readMentions         0x36e5bf4dU
#define MTPC_messages_readReactions        0x9ec44f93U
#define MTPC_messages_readPollVotes        0x1720b4d8U
#define MTPC_messages_reportReadMetrics    0x4067c5e6U

#define MTPC_stories_readStories           0xa556dac8U

#define MTPC_messages_readMessageContents  0x36a73f77U
#define MTPC_channels_readMessageContents  0xeab5dc38U

#define MTPC_messages_setTyping            0x58943ee2U
#define MTPC_messages_setEncryptedTyping   0x791451edU

#define MTPC_account_updateStatus          0x6628562cU
#define MTPC_boolFalse                     0xbc799737U
#define MTPC_boolTrue                      0x997275b5U

// ============================================================================
// Plugin State & Configuration
// ============================================================================
static bool g_block_read     = true;
static bool g_block_stories  = true;
static bool g_block_media    = true;
static bool g_block_typing   = true;
static bool g_hide_online    = false;
static bool g_flushing_now   = false;

static uint64_t g_stat_read    = 0;
static uint64_t g_stat_stories = 0;
static uint64_t g_stat_media   = 0;
static uint64_t g_stat_typing  = 0;

static intptr_t g_slide = 0;

typedef void (*fn_sendReadRequests_t)(void *histories);
typedef void (*fn_mtpSendRequest_t)(void *self, int32_t requestId, void *serializedRequest,
                                    void *responseHandler, int32_t dcId, int64_t msCanWait,
                                    int32_t afterRequestId);
typedef void (*fn_sessionSendPrepared_t)(void *session, void *serializedRequest, int64_t msCanWait);

static fn_sendReadRequests_t    orig_sendReadRequests    = NULL;
static fn_mtpSendRequest_t      orig_mtpSendRequest      = NULL;
static fn_sessionSendPrepared_t orig_sessionSendPrepared = NULL;

typedef struct {
    void   *history;
    int64_t till_id;
} pending_read_t;

#define MAX_PENDING_HISTORIES 128
static pending_read_t g_pending[MAX_PENDING_HISTORIES];
static size_t         g_pending_count  = 0;
static void          *g_last_histories = NULL;
static void          *g_last_history   = NULL;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

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

static void record_pending_read(void *history, int64_t till_id) {
    if (!history || till_id <= 0) return;
    g_last_history = history;
    for (size_t i = 0; i < g_pending_count; i++) {
        if (g_pending[i].history == history) {
            if (till_id > g_pending[i].till_id) {
                g_pending[i].till_id = till_id;
            }
            return;
        }
    }
    if (g_pending_count < MAX_PENDING_HISTORIES) {
        g_pending[g_pending_count].history = history;
        g_pending[g_pending_count].till_id = till_id;
        g_pending_count++;
    } else {
        g_pending[0].history = history;
        g_pending[0].till_id = till_id;
    }
}

static void update_ui_menus(void);

// ============================================================================
// Helper: Inspect & Filter MTProto SerializedRequest
// ============================================================================
static bool should_block_serialized_request(void *serializedRequest, const char *gate_name) {
    if (!serializedRequest) return false;
    void *qlist = *(void **)serializedRequest;
    if (!qlist) return false;

    uint32_t *primes = *(uint32_t **)((uint8_t *)qlist + 8);
    int64_t   count  = *(int64_t *)((uint8_t *)qlist + 16);
    if (!primes || count < 9) return false;

    uint32_t op = primes[8];

    switch (op) {
        case MTPC_messages_readHistory:
        case MTPC_channels_readHistory:
        case MTPC_messages_readEncryptedHistory:
        case MTPC_messages_readDiscussion:
        case MTPC_messages_readSavedHistory:
        case MTPC_messages_readMentions:
        case MTPC_messages_readReactions:
        case MTPC_messages_readPollVotes:
        case MTPC_messages_reportReadMetrics:
            if (g_block_read && !g_flushing_now) {
                g_stat_read++;
                ghost_log("[%s] BLOCKED read receipt RPC 0x%08x (total=%llu)",
                          gate_name, op, (unsigned long long)g_stat_read);
                dispatch_async(dispatch_get_main_queue(), ^{ update_ui_menus(); });
                return true;
            }
            break;

        case MTPC_stories_readStories:
            if (g_block_stories) {
                g_stat_stories++;
                ghost_log("[%s] BLOCKED stories.readStories 0x%08x (total=%llu)",
                          gate_name, op, (unsigned long long)g_stat_stories);
                dispatch_async(dispatch_get_main_queue(), ^{ update_ui_menus(); });
                return true;
            }
            break;

        case MTPC_messages_readMessageContents:
        case MTPC_channels_readMessageContents:
            if (g_block_media) {
                g_stat_media++;
                ghost_log("[%s] BLOCKED readMessageContents 0x%08x (total=%llu)",
                          gate_name, op, (unsigned long long)g_stat_media);
                dispatch_async(dispatch_get_main_queue(), ^{ update_ui_menus(); });
                return true;
            }
            break;

        case MTPC_messages_setTyping:
        case MTPC_messages_setEncryptedTyping:
            if (g_block_typing) {
                g_stat_typing++;
                ghost_log("[%s] BLOCKED setTyping 0x%08x (total=%llu)",
                          gate_name, op, (unsigned long long)g_stat_typing);
                dispatch_async(dispatch_get_main_queue(), ^{ update_ui_menus(); });
                return true;
            }
            break;

        case MTPC_account_updateStatus:
            if (g_hide_online && count >= 10 && primes[9] == MTPC_boolFalse) {
                primes[9] = MTPC_boolTrue;
                ghost_log("[%s] REWROTE account.updateStatus(offline=false -> true)", gate_name);
            }
            break;

        default:
            break;
    }
    return false;
}

// ============================================================================
// Hook 1: Data::Histories::sendReadRequests(Data::Histories *this)
// ============================================================================
static void hook_sendReadRequests(void *histories) {
    pthread_mutex_lock(&g_lock);
    g_last_histories = histories;

    if (g_block_read && !g_flushing_now && histories != NULL) {
        uint8_t *begin = *(uint8_t **)((uint8_t *)histories + 0x40);
        uint8_t *end   = *(uint8_t **)((uint8_t *)histories + 0x48);
        size_t suppressed = 0;

        if (begin && end && end >= begin && ((size_t)(end - begin) % 0x58 == 0)) {
            for (uint8_t *p = begin; p < end; p += 0x58) {
                void   *history      = *(void **)(p + 0x00);
                int64_t willReadTill = *(int64_t *)(p + 0x38);
                int64_t sentReadTill = *(int64_t *)(p + 0x40);
                if (willReadTill > sentReadTill && willReadTill > 0) {
                    record_pending_read(history, willReadTill);
                    *(int64_t *)(p + 0x38) = 0;
                    *(int64_t *)(p + 0x48) = 0;
                    *(uint8_t *)(p + 0x50) = 0;
                    suppressed++;
                    g_stat_read++;
                }
            }
        }
        pthread_mutex_unlock(&g_lock);

        if (suppressed > 0) {
            ghost_log("[Histories::sendReadRequests] Suppressed %zu chat read receipt(s) (total=%llu)",
                      suppressed, (unsigned long long)g_stat_read);
            dispatch_async(dispatch_get_main_queue(), ^{ update_ui_menus(); });
        }
        orig_sendReadRequests(histories);
        return;
    }

    pthread_mutex_unlock(&g_lock);
    orig_sendReadRequests(histories);
}

// ============================================================================
// Hook 2: MTP::Instance::Private::sendRequest
// ============================================================================
static void hook_mtpSendRequest(void *self, int32_t requestId, void *serializedRequest,
                                void *responseHandler, int32_t dcId, int64_t msCanWait,
                                int32_t afterRequestId) {
    if (should_block_serialized_request(serializedRequest, "MTP::sendRequest")) {
        return;
    }
    orig_mtpSendRequest(self, requestId, serializedRequest, responseHandler,
                        dcId, msCanWait, afterRequestId);
}

// ============================================================================
// Hook 3: MTP::details::Session::sendPrepared
// ============================================================================
static void hook_sessionSendPrepared(void *session, void *serializedRequest, int64_t msCanWait) {
    if (should_block_serialized_request(serializedRequest, "Session::sendPrepared")) {
        return;
    }
    orig_sessionSendPrepared(session, serializedRequest, msCanWait);
}

// ============================================================================
// Persistence & Native macOS UI (In-Window Floating Pill + HUD Panel + Menu Bar)
// ============================================================================
static NSString * const kPrefBlockRead    = @"TGGhost_BlockRead";
static NSString * const kPrefBlockStories = @"TGGhost_BlockStories";
static NSString * const kPrefBlockMedia   = @"TGGhost_BlockMedia";
static NSString * const kPrefBlockTyping  = @"TGGhost_BlockTyping";
static NSString * const kPrefHideOnline   = @"TGGhost_HideOnline";

static void load_preferences(void) {
    NSUserDefaults *defs = [NSUserDefaults standardUserDefaults];
    if ([defs objectForKey:kPrefBlockRead] != nil)
        g_block_read = [defs boolForKey:kPrefBlockRead];
    if ([defs objectForKey:kPrefBlockStories] != nil)
        g_block_stories = [defs boolForKey:kPrefBlockStories];
    if ([defs objectForKey:kPrefBlockMedia] != nil)
        g_block_media = [defs boolForKey:kPrefBlockMedia];
    if ([defs objectForKey:kPrefBlockTyping] != nil)
        g_block_typing = [defs boolForKey:kPrefBlockTyping];
    if ([defs objectForKey:kPrefHideOnline] != nil)
        g_hide_online = [defs boolForKey:kPrefHideOnline];
}

static void save_preferences(void) {
    NSUserDefaults *defs = [NSUserDefaults standardUserDefaults];
    [defs setBool:g_block_read    forKey:kPrefBlockRead];
    [defs setBool:g_block_stories forKey:kPrefBlockStories];
    [defs setBool:g_block_media   forKey:kPrefBlockMedia];
    [defs setBool:g_block_typing  forKey:kPrefBlockTyping];
    [defs setBool:g_hide_online   forKey:kPrefHideOnline];
    [defs synchronize];
}

@interface TGGhostMenuController : NSObject
@property (nonatomic, strong) NSStatusItem *statusItem;
@property (nonatomic, strong) NSMenuItem   *appBarRootItem;
@property (nonatomic, strong) NSButton     *windowBadgeButton;
@property (nonatomic, strong) NSPanel      *hudPanel;
@property (nonatomic, strong) NSSwitch     *swRead;
@property (nonatomic, strong) NSSwitch     *swStories;
@property (nonatomic, strong) NSSwitch     *swMedia;
@property (nonatomic, strong) NSSwitch     *swTyping;
@property (nonatomic, strong) NSSwitch     *swOnline;
@property (nonatomic, strong) NSTextField  *lblStats;
- (void)setupMenus;
- (void)refreshState;
@end

static TGGhostMenuController *g_menuController = nil;

@implementation TGGhostMenuController

- (NSMenu *)buildGhostMenu {
    NSMenu *menu = [[NSMenu alloc] initWithTitle:@"👻 Hayalet Mod"];
    [menu setAutoenablesItems:NO];

    NSMenuItem *itemPanel = [[NSMenuItem alloc] initWithTitle:@"🎛️ Hayalet Mod Ayar Panelini Aç"
                                                       action:@selector(showHudPanel:)
                                                keyEquivalent:@"g"];
    [itemPanel setKeyEquivalentModifierMask:(NSEventModifierFlagCommand | NSEventModifierFlagOption)];
    [itemPanel setTarget:self];
    [menu addItem:itemPanel];

    [menu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *itemRead = [[NSMenuItem alloc] initWithTitle:@"👻 Mesaj Görüldüsünü Kapat (Ghost Mode)"
                                                      action:@selector(toggleBlockRead:)
                                               keyEquivalent:@"g"];
    [itemRead setKeyEquivalentModifierMask:(NSEventModifierFlagCommand | NSEventModifierFlagShift)];
    [itemRead setTarget:self];
    [itemRead setTag:101];
    [menu addItem:itemRead];

    NSMenuItem *itemStories = [[NSMenuItem alloc] initWithTitle:@"📖 Hikaye (Story) Görüldüsünü Kapat"
                                                         action:@selector(toggleBlockStories:)
                                                  keyEquivalent:@""];
    [itemStories setTarget:self];
    [itemStories setTag:102];
    [menu addItem:itemStories];

    NSMenuItem *itemMedia = [[NSMenuItem alloc] initWithTitle:@"🎤 Sesli Mesaj / Medya Açıldı Bilgisini Kapat"
                                                       action:@selector(toggleBlockMedia:)
                                                keyEquivalent:@""];
    [itemMedia setTarget:self];
    [itemMedia setTag:103];
    [menu addItem:itemMedia];

    NSMenuItem *itemTyping = [[NSMenuItem alloc] initWithTitle:@"⌨️ 'Yazıyor / Kaydediyor...' Bilgisini Gizle"
                                                        action:@selector(toggleBlockTyping:)
                                                 keyEquivalent:@"t"];
    [itemTyping setKeyEquivalentModifierMask:(NSEventModifierFlagCommand | NSEventModifierFlagShift)];
    [itemTyping setTarget:self];
    [itemTyping setTag:104];
    [menu addItem:itemTyping];

    NSMenuItem *itemOnline = [[NSMenuItem alloc] initWithTitle:@"🕶️ Çevrimiçi (Online) Durumunu Gizle"
                                                        action:@selector(toggleHideOnline:)
                                                 keyEquivalent:@""];
    [itemOnline setTarget:self];
    [itemOnline setTag:105];
    [menu addItem:itemOnline];

    [menu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *itemFlush = [[NSMenuItem alloc] initWithTitle:@"✅ Son Sohbete Şimdi Görüldü Gönder"
                                                       action:@selector(flushLastHistoryRead:)
                                                keyEquivalent:@"r"];
    [itemFlush setKeyEquivalentModifierMask:(NSEventModifierFlagCommand | NSEventModifierFlagShift)];
    [itemFlush setTarget:self];
    [itemFlush setTag:201];
    [menu addItem:itemFlush];

    [menu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *itemStats = [[NSMenuItem alloc] initWithTitle:@"Engellenen: 0 Görüldü"
                                                       action:nil
                                                keyEquivalent:@""];
    [itemStats setEnabled:NO];
    [itemStats setTag:301];
    [menu addItem:itemStats];

    return menu;
}

- (NSSwitch *)addSwitchRowToView:(NSView *)parent
                           title:(NSString *)title
                        subtitle:(NSString *)subtitle
                           yPos:(CGFloat)y
                         action:(SEL)action {
    NSTextField *lbl = [NSTextField labelWithString:title];
    lbl.font = [NSFont systemFontOfSize:13 weight:NSFontWeightMedium];
    lbl.textColor = [NSColor whiteColor];
    lbl.frame = NSMakeRect(18, y + 14, 260, 18);
    [parent addSubview:lbl];

    NSTextField *sub = [NSTextField labelWithString:subtitle];
    sub.font = [NSFont systemFontOfSize:11 weight:NSFontWeightRegular];
    sub.textColor = [NSColor colorWithWhite:0.72 alpha:1.0];
    sub.frame = NSMakeRect(18, y - 2, 260, 15);
    [parent addSubview:sub];

    NSSwitch *sw = [[NSSwitch alloc] initWithFrame:NSMakeRect(292, y + 4, 42, 24)];
    sw.target = self;
    sw.action = action;
    [parent addSubview:sw];
    return sw;
}

- (void)buildHudPanelIfNeeded {
    if (self.hudPanel) return;

    NSRect rect = NSMakeRect(0, 0, 355, 340);
    NSPanel *panel = [[NSPanel alloc] initWithContentRect:rect
                                                styleMask:(NSWindowStyleMaskTitled |
                                                           NSWindowStyleMaskClosable |
                                                           NSWindowStyleMaskUtilityWindow |
                                                           NSWindowStyleMaskFullSizeContentView)
                                                  backing:NSBackingStoreBuffered
                                                    defer:NO];
    panel.title = @"👻 Telegram Hayalet Mod (Ghost Plugin)";
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

    self.swRead = [self addSwitchRowToView:bg
                                     title:@"👻 Mesaj Görüldüsünü Kapat"
                                  subtitle:@"Sohbetleri okusan da karşıya çift tık gitmez (⌘⇧G)"
                                      yPos:258
                                    action:@selector(toggleBlockRead:)];

    self.swStories = [self addSwitchRowToView:bg
                                        title:@"📖 Hikaye (Story) Görüldüsünü Kapat"
                                     subtitle:@"Hikayeleri izlediğinde izleyenler listesinde çıkmazsın"
                                         yPos:208
                                       action:@selector(toggleBlockStories:)];

    self.swMedia = [self addSwitchRowToView:bg
                                      title:@"🎤 Sesli Mesaj / Medya Açıldı Kapat"
                                   subtitle:@"Sesli/yuvarlak videoları dinlediğin karşıda görünmez"
                                       yPos:158
                                     action:@selector(toggleBlockMedia:)];

    self.swTyping = [self addSwitchRowToView:bg
                                       title:@"⌨️ 'Yazıyor / Kaydediyor...' Gizle"
                                    subtitle:@"Mesaj yazarken veya ses kaydederken bildirim gitmez (⌘⇧T)"
                                        yPos:108
                                      action:@selector(toggleBlockTyping:)];

    self.swOnline = [self addSwitchRowToView:bg
                                       title:@"🕶️ Çevrimiçi (Online) Durumunu Gizle"
                                    subtitle:@"Telegram açıkken bile sunucuya Offline bildirir"
                                        yPos:58
                                      action:@selector(toggleHideOnline:)];

    NSButton *flushBtn = [NSButton buttonWithTitle:@"✅ Son Açılan Sohbete Şimdi Görüldü Gönder (⌘⇧R)"
                                            target:self
                                            action:@selector(flushLastHistoryRead:)];
    flushBtn.bezelStyle = NSBezelStyleRounded;
    flushBtn.frame = NSMakeRect(16, 22, 323, 28);
    [bg addSubview:flushBtn];

    self.lblStats = [NSTextField labelWithString:@"📊 Engellenen: 0 Görüldü | 0 Story | 0 Yazıyor"];
    self.lblStats.font = [NSFont monospacedDigitSystemFontOfSize:11 weight:NSFontWeightRegular];
    self.lblStats.textColor = [NSColor colorWithRed:0.45 green:0.85 blue:0.55 alpha:1.0];
    self.lblStats.alignment = NSTextAlignmentCenter;
    self.lblStats.frame = NSMakeRect(16, 4, 323, 15);
    [bg addSubview:self.lblStats];

    self.hudPanel = panel;
}

- (void)attachInWindowBadgeIfNeeded {
    NSWindow *mainWin = nil;
    for (NSWindow *win in [NSApp windows]) {
        if (win != self.hudPanel && win.isVisible && win.frame.size.width > 300 && win.frame.size.height > 300) {
            mainWin = win;
            break;
        }
    }
    if (!mainWin) return;

    NSView *themeFrame = mainWin.contentView.superview ?: mainWin.contentView;
    if (!themeFrame) return;

    if (!self.windowBadgeButton) {
        NSButton *btn = [[NSButton alloc] initWithFrame:NSMakeRect(themeFrame.bounds.size.width - 118,
                                                                   themeFrame.bounds.size.height - 32,
                                                                   106, 24)];
        btn.bezelStyle = NSBezelStyleAccessoryBarAction;
        btn.wantsLayer = YES;
        btn.layer.cornerRadius = 11.0;
        btn.layer.backgroundColor = [NSColor colorWithRed:0.12 green:0.14 blue:0.18 alpha:0.90].CGColor;
        btn.font = [NSFont systemFontOfSize:12 weight:NSFontWeightSemibold];
        btn.target = self;
        btn.action = @selector(showHudPanel:);
        btn.toolTip = @"Telegram Hayalet Mod Ayarları (Tıkla)";
        btn.autoresizingMask = (NSViewMinXMargin | NSViewMinYMargin);
        self.windowBadgeButton = btn;
    }

    if (self.windowBadgeButton.superview != themeFrame) {
        [self.windowBadgeButton removeFromSuperview];
        self.windowBadgeButton.frame = NSMakeRect(themeFrame.bounds.size.width - 118,
                                                  themeFrame.bounds.size.height - 32,
                                                  106, 24);
        [themeFrame addSubview:self.windowBadgeButton];
        ghost_log("[UI] Attached in-window Ghost button to Telegram window (%p)", mainWin);
    }
}

- (void)setupMenus {
    if (!self.statusItem) {
        self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
        self.statusItem.menu = [self buildGhostMenu];
    }

    NSMenu *mainMenu = [NSApp mainMenu];
    if (mainMenu) {
        NSMenuItem *existing = [mainMenu itemWithTitle:@"👻 Hayalet Mod"];
        if (!existing) {
            self.appBarRootItem = [[NSMenuItem alloc] initWithTitle:@"👻 Hayalet Mod"
                                                             action:nil
                                                      keyEquivalent:@""];
            self.appBarRootItem.submenu = [self buildGhostMenu];
            [mainMenu addItem:self.appBarRootItem];
            ghost_log("[UI] Added '👻 Hayalet Mod' to [NSApp mainMenu]");
        }
    }

    [self buildHudPanelIfNeeded];
    [self attachInWindowBadgeIfNeeded];
    [self refreshState];
}

- (void)showHudPanel:(id)sender {
    [self buildHudPanelIfNeeded];
    [self refreshState];
    if (self.hudPanel.isVisible) {
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

- (void)updateMenuInstance:(NSMenu *)menu {
    if (!menu) return;
    [[menu itemWithTag:101] setState:(g_block_read    ? NSControlStateValueOn : NSControlStateValueOff)];
    [[menu itemWithTag:102] setState:(g_block_stories ? NSControlStateValueOn : NSControlStateValueOff)];
    [[menu itemWithTag:103] setState:(g_block_media   ? NSControlStateValueOn : NSControlStateValueOff)];
    [[menu itemWithTag:104] setState:(g_block_typing  ? NSControlStateValueOn : NSControlStateValueOff)];
    [[menu itemWithTag:105] setState:(g_hide_online   ? NSControlStateValueOn : NSControlStateValueOff)];

    NSString *stats = [NSString stringWithFormat:@"📊 Engellenen: %llu Görüldü | %llu Story | %llu Yazıyor",
                       (unsigned long long)g_stat_read,
                       (unsigned long long)g_stat_stories,
                       (unsigned long long)g_stat_typing];
    [[menu itemWithTag:301] setTitle:stats];
}

- (void)refreshState {
    if (self.statusItem.button) {
        self.statusItem.button.title = g_block_read ? @"👻 TG" : @"👁️ TG";
    }
    if (self.windowBadgeButton) {
        NSString *badgeTitle = g_block_read ? @"👻 Hayalet: AÇIK" : @"👁️ Hayalet: KAPALI";
        NSMutableAttributedString *attr = [[NSMutableAttributedString alloc] initWithString:badgeTitle];
        NSColor *fg = g_block_read
            ? [NSColor colorWithRed:0.45 green:0.95 blue:0.60 alpha:1.0]
            : [NSColor colorWithRed:1.00 green:0.65 blue:0.35 alpha:1.0];
        [attr addAttributes:@{
            NSForegroundColorAttributeName: fg,
            NSFontAttributeName: [NSFont systemFontOfSize:11 weight:NSFontWeightBold]
        } range:NSMakeRange(0, attr.length)];
        self.windowBadgeButton.attributedTitle = attr;
    }

    if (self.swRead)    self.swRead.state    = g_block_read    ? NSControlStateValueOn : NSControlStateValueOff;
    if (self.swStories) self.swStories.state = g_block_stories ? NSControlStateValueOn : NSControlStateValueOff;
    if (self.swMedia)   self.swMedia.state   = g_block_media   ? NSControlStateValueOn : NSControlStateValueOff;
    if (self.swTyping)  self.swTyping.state  = g_block_typing  ? NSControlStateValueOn : NSControlStateValueOff;
    if (self.swOnline)  self.swOnline.state  = g_hide_online   ? NSControlStateValueOn : NSControlStateValueOff;

    if (self.lblStats) {
        self.lblStats.stringValue = [NSString stringWithFormat:@"📊 Engellenen: %llu Görüldü | %llu Story | %llu Yazıyor",
                                     (unsigned long long)g_stat_read,
                                     (unsigned long long)g_stat_stories,
                                     (unsigned long long)g_stat_typing];
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

- (void)flushLastHistoryRead:(id)sender {
    pthread_mutex_lock(&g_lock);
    void *histories = g_last_histories;
    void *target_history = g_last_history;
    int64_t target_till = 0;

    for (size_t i = 0; i < g_pending_count; i++) {
        if (g_pending[i].history == target_history) {
            target_till = g_pending[i].till_id;
            break;
        }
    }

    if (histories && target_history && target_till > 0) {
        uint8_t *begin = *(uint8_t **)((uint8_t *)histories + 0x40);
        uint8_t *end   = *(uint8_t **)((uint8_t *)histories + 0x48);
        if (begin && end && end >= begin && ((size_t)(end - begin) % 0x58 == 0)) {
            for (uint8_t *p = begin; p < end; p += 0x58) {
                if (*(void **)(p + 0x00) == target_history) {
                    int64_t sent = *(int64_t *)(p + 0x40);
                    if (target_till > sent) {
                        *(int64_t *)(p + 0x38) = target_till;
                        *(int64_t *)(p + 0x48) = 0;
                    }
                    break;
                }
            }
        }
        g_flushing_now = true;
        pthread_mutex_unlock(&g_lock);

        ghost_log("[UI] Flushing read receipt for last history %p till %lld",
                  target_history, (long long)target_till);
        orig_sendReadRequests(histories);

        pthread_mutex_lock(&g_lock);
        g_flushing_now = false;
        pthread_mutex_unlock(&g_lock);
    } else {
        pthread_mutex_unlock(&g_lock);
        ghost_log("[UI] Flush requested, but no pending history read receipt found");
    }
    [self refreshState];
}

@end

static void ensure_ui_setup_on_main(void) {
    if (!g_menuController) {
        g_menuController = [[TGGhostMenuController alloc] init];
    }
    [g_menuController setupMenus];
}

static void update_ui_menus(void) {
    CFRunLoopRef mainLoop = CFRunLoopGetMain();
    if (mainLoop) {
        CFRunLoopPerformBlock(mainLoop, kCFRunLoopCommonModes, ^{
            ensure_ui_setup_on_main();
        });
        CFRunLoopWakeUp(mainLoop);
    }
}

static void *ui_watchdog_thread(void *arg) {
    for (int i = 0; i < 30; i++) {
        usleep(1000 * 1000); // 1s
        update_ui_menus();
    }
    return NULL;
}

// ============================================================================
// Constructor: Install Hooks & Schedule UI Setup
// ============================================================================
__attribute__((constructor))
static void tg_ghost_init(void) {
    load_preferences();

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (hdr && hdr->filetype == MH_EXECUTE) {
            g_slide = _dyld_get_image_vmaddr_slide(i);
            break;
        }
    }

    orig_sendReadRequests    = (fn_sendReadRequests_t)(g_slide + VA_CAVE_ORIG_SEND_READ_REQ);
    orig_mtpSendRequest      = (fn_mtpSendRequest_t)(g_slide + VA_CAVE_ORIG_MTP_SEND_REQ);
    orig_sessionSendPrepared = (fn_sessionSendPrepared_t)(g_slide + VA_CAVE_ORIG_SESSION_SEND);

    uint32_t insn1 = *(uint32_t *)orig_sendReadRequests;
    uint32_t insn2 = *(uint32_t *)orig_mtpSendRequest;
    uint32_t insn3 = *(uint32_t *)orig_sessionSendPrepared;

    if (insn1 == 0xd10383ff && insn2 == 0xd10183ff && insn3 == 0xd10243ff) {
        *(void **)(g_slide + VA_PTR_HOOK_SEND_READ_REQ) = (void *)&hook_sendReadRequests;
        *(void **)(g_slide + VA_PTR_HOOK_MTP_SEND_REQ)  = (void *)&hook_mtpSendRequest;
        *(void **)(g_slide + VA_PTR_HOOK_SESSION_SEND)  = (void *)&hook_sessionSendPrepared;
        ghost_log("Telegram Ghost Plugin loaded! slide=0x%lx read=%d stories=%d media=%d typing=%d online=%d",
                  (unsigned long)g_slide, (int)g_block_read, (int)g_block_stories,
                  (int)g_block_media, (int)g_block_typing, (int)g_hide_online);
    } else {
        ghost_log("WARNING: Unexpected trampoline bytes (%08x %08x %08x), hooks not activated.",
                  insn1, insn2, insn3);
        return;
    }

    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    [nc addObserverForName:NSWindowDidBecomeKeyNotification
                    object:nil
                     queue:[NSOperationQueue mainQueue]
                usingBlock:^(NSNotification * _Nonnull note) {
        ensure_ui_setup_on_main();
    }];

    pthread_t tid;
    pthread_create(&tid, NULL, ui_watchdog_thread, NULL);
    pthread_detach(tid);
}
