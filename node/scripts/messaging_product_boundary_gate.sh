#!/usr/bin/env bash
# Fail closed if the shipping serverless product drifts back toward a public
# social network or a silent FastAPI / central-inbox path.
#
# Current main ships the terminal node (raven-core / ash / raven-node /
# raven-swarm). The historical iOS/Watch surface is not in this tree; if those
# directories return, the original iOS/Watch refusals run fail-closed as well.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export RAVEN_BOUNDARY_ROOT="$ROOT"

python3 <<'PY'
from pathlib import Path
import os
import re
import sys

root = Path(os.environ["RAVEN_BOUNDARY_ROOT"])
ios = root / "ios-native" / "RAVEN"
watch_root = root / "RAVEN-WatchApp" / "RAVEN-Watch"
failures: list[str] = []


def read_path(path: Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        failures.append(f"missing/unreadable {label}: {exc}")
        return ""


def require_text(source: str, needle: str, label: str) -> None:
    if needle not in source:
        failures.append(f"{label}: required marker missing")


# ---------------------------------------------------------------------------
# Serverless node product (always — this is what main ships)
# ---------------------------------------------------------------------------

messaging = read_path(
    root / "node/crates/raven-core/src/messaging_path.rs",
    "node/crates/raven-core/src/messaging_path.rs",
)
require_text(
    messaging,
    "REFUSE: serverless path must never silently use FastAPI for message delivery",
    "messaging_path FastAPI refuse",
)
require_text(messaging, "fn resolve_terminal_messaging_path", "terminal path resolver")
require_text(messaging, "ServerlessRvn1", "serverless path variant")
require_text(messaging, "allowed_for_serverless_binary", "serverless-binary allowlist")
if "return MessagingPath::LegacyFastApi" in messaging:
    failures.append("messaging_path.rs must not select LegacyFastApi as an active path")

for rel in (
    "node/crates/raven-core/Cargo.toml",
    "node/crates/raven-node/Cargo.toml",
    "node/crates/ash/Cargo.toml",
):
    text = read_path(root / rel, rel)
    default = re.search(r"(?m)^default\s*=\s*\[([^\]]*)\]", text)
    if not default:
        failures.append(f"{rel}: missing default features list")
        continue
    if "unsafe-demo-crypto" in default.group(1):
        failures.append(f"{rel}: unsafe-demo-crypto must not be a default feature")

shipping_src = [
    root / "node/crates/raven-core/src",
    root / "node/crates/raven-node/src",
    root / "node/crates/ash/src",
    root / "node/crates/raven-swarm/src",
]
social_needles = (
    "/api/posts",
    "/api/events/action",
    "FeedView(",
    "DiscoverView(",
    "NewPostView(",
    "ClubView(",
)
for src_root in shipping_src:
    if not src_root.is_dir():
        failures.append(f"missing shipping crate source tree: {src_root.relative_to(root)}")
        continue
    for path in src_root.rglob("*.rs"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        rel = path.relative_to(root)
        for needle in social_needles:
            if needle in text:
                failures.append(f"shipping source reintroduces social/central surface in {rel}: {needle}")

node_main = read_path(root / "node/crates/raven-node/src/main.rs", "raven-node main")
require_text(node_main, "RAVEN serverless local node", "raven-node product label")


# ---------------------------------------------------------------------------
# Historical iOS / Watch refusals — only when those trees are present
# ---------------------------------------------------------------------------

def function_body(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0:
        return ""
    brace = source.find("{", start)
    if brace < 0:
        return ""
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1:index]
    return ""


def read(relative: str) -> str:
    path = ios / relative
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        failures.append(f"missing/unreadable {relative}: {exc}")
        return ""


def require(relative: str, needle: str, label: str) -> None:
    if needle not in read(relative):
        failures.append(f"{label}: required marker missing from {relative}")


def check_ios_watch_surface() -> None:
    main_shell = read("RAVEN/Views/MainShellView.swift")
    for symbol in ("FeedView(", "DiscoverView(", "NewPostView(", "ClubView("):
        if symbol in main_shell:
            failures.append(f"root-shell exposes social surface: {symbol}")

    onboarding = read("RAVEN/Features/Onboarding/OnboardingView.swift")
    for legacy in ("Local + Friends Feed", "friends' posts", "friends’ posts"):
        if legacy in onboarding:
            failures.append(f"onboarding advertises social product: {legacy}")
    if "without turning them into a public feed" not in onboarding:
        failures.append("onboarding messaging-only boundary marker missing")

    deep_links = read("RAVEN/Core/Push/DeepLinkRouter.swift")
    route_body = function_body(deep_links, "func routeFor")
    if not route_body:
        failures.append("DeepLinkRouter.routeFor not found")
    for kind in ("post", "echo", "club", "room"):
        if re.search(rf'case\s+[^\n]*"{kind}"', route_body):
            failures.append(f"external deep-link parser admits social kind: {kind}")
    central_route = function_body(deep_links, "func route(to destination")
    if "guard destination.isMessagingProductDestination else" not in central_route:
        failures.append("central deep-link route lacks messaging-product admission guard")

    push = read("RAVEN/Core/Push/PushNotificationService.swift")
    parse_push = function_body(push, "func parsePushPayload")
    if not parse_push:
        failures.append("PushNotificationService.parsePushPayload not found")
    if "PushPayload.parseMessaging(userInfo)" not in parse_push:
        failures.append("push actor bypasses pure messaging admission parser")
    parse_messaging_push = function_body(push, "static func parseMessaging")
    if not parse_messaging_push:
        failures.append("PushPayload.parseMessaging not found")
    if "type.isMessagingProductEvent" not in parse_messaging_push:
        failures.append("pure push parser lacks messaging-product admission guard")
    if "?? .message" in parse_push or "?? .message" in parse_messaging_push:
        failures.append("unknown push type still falls back to message")

    for signature in (
        "private func handleForegroundPush",
        "private func routeToDestination",
        "private func scheduleLocalNotificationForBackground",
    ):
        body = function_body(push, signature)
        if not body:
            failures.append(f"push side-effect boundary not found: {signature}")
        elif "guard payload.type.isMessagingProductEvent else" not in body:
            failures.append(f"push side-effect boundary lacks messaging guard: {signature}")
    for forbidden in (
        "ToastItem.comment(",
        "ToastItem.like(",
        ".route(to: .post",
        ".route(to: .audioRoom",
    ):
        if forbidden in push:
            failures.append(f"push actor retains executable social behavior: {forbidden}")

    notifications_service = read("RAVEN/Core/Notifications/NotificationsService.swift")
    if r"let notifications = fetched.filter(\.isMessagingProductEvent)" not in notifications_service:
        failures.append("notification polling does not filter server rows before badges/toasts")
    create_toast = function_body(notifications_service, "private func createToast")
    if not create_toast:
        failures.append("NotificationsService.createToast not found")
    elif "guard notification.isMessagingProductEvent else" not in create_toast:
        failures.append("server notification formatter lacks messaging admission guard")
    for forbidden in (
        "ToastItem.like(",
        "ToastItem.comment(",
        'case "audio_room"',
        "Generic notification",
    ):
        if forbidden in create_toast:
            failures.append(f"server notification formatter retains social/generic escape: {forbidden}")

    require(
        "RAVEN/Features/Notifications/NotificationsListView.swift",
        "allowedServerTypes",
        "notification source allowlist",
    )
    require(
        "RAVEN/Core/Notifications/NotificationPipeline.swift",
        "guard item.type.isMessagingProductEvent else",
        "toast admission guard",
    )
    require(
        "RAVEN/Core/Realtime/RealtimeEngine.swift",
        "messagingEventTypes",
        "realtime messaging allowlist",
    )
    realtime = read("RAVEN/Core/Realtime/RealtimeEngine.swift")
    realtime_toast = function_body(realtime, "private func showToast")
    for forbidden in ("ToastItem.like(", "ToastItem.comment(", 'case "new_post"', 'case "post"'):
        if forbidden in realtime_toast:
            failures.append(f"realtime toast path retains social conversion: {forbidden}")

    toast_item = read("RAVEN/Core/Notifications/ToastItem.swift")
    for forbidden in (
        "static func like(",
        "static func comment(",
        "liked your post",
        "commented on your post",
    ):
        if forbidden in toast_item:
            failures.append(f"toast model retains active social formatter: {forbidden}")

    telemetry = read("RAVEN/Core/Telemetry/UserActionTelemetry.swift")
    for forbidden in ("/api/events/action", "NetworkService.shared", "Task.detached"):
        if forbidden in telemetry:
            failures.append(f"central behavioral telemetry remains active: {forbidden}")

    tracker = ios / "RAVEN" / "Core" / "Services" / "ContentConsumptionTracker.swift"
    if tracker.exists():
        failures.append("ContentConsumptionTracker.swift still exists")
    project = read("RAVEN.xcodeproj/project.pbxproj")
    for removed in ("ContentConsumptionTracker.swift", "MeshSuccessToast.swift", "TranscriptionService.swift"):
        if removed in project:
            failures.append(f"removed social source remains in Xcode project: {removed}")

    runtime_tests = read("RAVENTests/MessagingProductBoundaryTests.swift")
    for marker in (
        "testLegacySocialDestinationsAreRefusedBeforeNavigation",
        "testPushParserFailsClosedForUnknownAndRetiredSocialTypes",
        "ServerNotification.isMessagingProductEventType",
        "testWatchSnapshotMigrationIgnoresOldSocialFieldsAndFiltersEvents",
    ):
        if marker not in runtime_tests:
            failures.append(f"runtime product-boundary coverage missing: {marker}")
    if "MessagingProductBoundaryTests.swift in Sources" not in project:
        failures.append("runtime product-boundary tests are not in RAVENTests Sources")
    if "WATCHMODELSTESTBUILD001" not in project:
        failures.append("actual WatchModels.swift is not compiled into boundary tests")

    share_links = read("RAVEN/Core/Share/RavenShareLink.swift")
    for forbidden in ("case post", "case echo", "case club", "case audioRoom", "Follow "):
        if forbidden in share_links:
            failures.append(f"public-content share link remains active: {forbidden}")

    watch_bridge = read("RAVEN/Core/Mesh/WatchBridgeService.swift")
    for forbidden in ("post-toggle-like", "post-comment", "room-membership", "room-ptt", "pushPostUpdate"):
        if forbidden in watch_bridge:
            failures.append(f"iPhone Watch bridge admits retired social intent: {forbidden}")

    watch_projector = read("RAVEN/Core/Mesh/WatchSnapshotProjector.swift")
    if '["raven.auth.token": token]' in watch_projector:
        failures.append("iPhone Watch projector still writes a plaintext bearer token")
    if "makeEncryptedAuthPayload" not in watch_projector:
        failures.append("Watch auth publication lacks encrypted-only payload boundary")

    for relative in ("Services/PhoneBridge.swift", "Services/RemoteAPI.swift", "Services/WatchStore.swift"):
        path = watch_root / relative
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as exc:
            failures.append(f"missing/unreadable Watch source {relative}: {exc}")
            continue
        for forbidden in ("/api/posts", "post-toggle-like", "post-comment", "togglePostLike", "commentOnPost"):
            if forbidden in source:
                failures.append(f"Watch active service retains public-content behavior in {relative}: {forbidden}")

    settings_files = (
        "RAVEN/Features/Settings/PrivacySettingsView.swift",
        "RAVEN/Features/Settings/NotificationsSettingsView.swift",
        "RAVEN/Features/Settings/FAQView.swift",
        "RAVEN/Features/Settings/PrivacyPolicyView.swift",
    )
    settings_forbidden = (
        "Show Liked Posts",
        "Show Replies",
        "Likes & Comments",
        "New Posts",
        "Audio Rooms",
        "Profile Views",
        "Posts & Feed",
        "Echo, Club",
        "Stories, Discovery",
    )
    for relative in settings_files:
        source = read(relative)
        for needle in settings_forbidden:
            if needle in source:
                failures.append(f"user-visible social setting/help remains in {relative}: {needle}")

    about = read("RAVEN/Features/Settings/AboutView.swift")
    if "private let sectionCount = 19" not in about or '"tos.s\\(i).content".localized' not in about:
        failures.append("TermsOfService active localization contract changed without boundary review")

    resources = ios / "RAVEN" / "Resources"
    retired_terms = (
        "Posts, Stories & Visibility",
        "Voice Rooms",
        "Publicaciones, Stories y Visibilidad",
        "Salas de Voz",
        "Beiträge, Stories & Sichtbarkeit",
        "Sprachräume",
        "پست‌ها، استوری‌ها و نمایش",
        "اتاق‌های صوتی",
        "投稿、ストーリー、公開設定",
        "ボイスルーム",
        "Посты, сторис и видимость",
        "Голосовые комнаты",
        "帖子、动态与可见性",
        "语音房间",
    )
    for path in sorted(resources.glob("*.lproj/Localizable.strings")):
        source = path.read_text(encoding="utf-8")
        terms_lines = "\n".join(
            line for line in source.splitlines() if line.lstrip().startswith('"tos.s')
        )
        for needle in retired_terms:
            if needle in terms_lines:
                failures.append(f"active Terms copy retains social feature in {path.relative_to(ios)}: {needle}")

    english_terms = read("RAVEN/Resources/en.lproj/Localizable.strings")
    for marker in (
        '"tos.s4.title" = "4. Your Messages and Files";',
        "Send or share illegal, violent, or abusive material in conversations",
        "Raven does not operate a global content-removal feed.",
        '"tos.s8.title" = "8. Private Conversations and Visibility";',
        "Raven has no public feed, follower audience, or public publishing mode.",
        '"tos.s9.title" = "9. Private Calls";',
    ):
        if marker not in english_terms:
            failures.append(f"English Terms messaging boundary marker missing: {marker}")

    report = read("RAVEN/Features/Moderation/ReportView.swift")
    for forbidden in (
        "case post =",
        "case comment =",
        "case room =",
        "case story =",
        "profile, posts, or message",
    ):
        if forbidden in report:
            failures.append(f"report UI exposes retired social target/copy: {forbidden}")

    chat = read("RAVEN/Features/Chat/ChatView.swift")
    if "posts, stories, or messages" in chat:
        failures.append("chat block confirmation advertises social objects")
    require(
        "RAVEN/Services/ModerationService.swift",
        'default: "Legacy record"',
        "legacy moderation records use neutral label",
    )

    app = read("RAVEN/App/RAVENApp.swift")
    shortcut = re.search(r'case\s+"app\.raven\.shortcut\.newPost"\s*:(.*?)(?=\n\s*case|\n\s*default)', app, re.S)
    if not shortcut or "return false" not in shortcut.group(1) or ".newPost" in shortcut.group(1):
        failures.append("legacy newPost shortcut is not an explicit fail-closed rejection")


if ios.is_dir() or watch_root.is_dir():
    if not ios.is_dir():
        failures.append("Watch tree present without ios-native/RAVEN — incomplete product surface")
    if not watch_root.is_dir():
        failures.append("ios-native/RAVEN present without RAVEN-WatchApp — incomplete product surface")
    if ios.is_dir() and watch_root.is_dir():
        check_ios_watch_surface()
else:
    print("iOS/Watch product trees absent — applying serverless-node boundary only")

if failures:
    print("MESSAGING_PRODUCT_BOUNDARY: FAIL", file=sys.stderr)
    for failure in failures:
        print(f" - {failure}", file=sys.stderr)
    raise SystemExit(1)

print("MESSAGING_PRODUCT_BOUNDARY: PASS")
print("legacy model/storage schemas are migration-only and are not release proof")
PY
