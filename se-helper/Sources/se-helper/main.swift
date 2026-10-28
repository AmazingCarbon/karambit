// karambit-se-helper: the only component that touches the Secure Enclave and Touch ID.
//
// Protocol (all output is JSON on stdout, errors as {"error": "..."} + non-zero exit):
//   keygen   --dir D            create bio.key + open.key + agent.key (fails if any exist), print pubkeys
//   addkey   --dir D --tier agent  create one missing key (never overwrites), print {tier: pubkey}
//   pubkeys  --dir D            print {"bio": b64(x963), "open": ..., "agent": ... (if present)}
//   ecdh     --dir D --prompt JSON stdin {"requests":[{"tier":"bio|open|agent","eph":b64}]}
//                               -> {"shared":[b64,...]}  (one Touch ID prompt for the whole batch)
//   auth     --prompt JSON         Touch ID policy gate only (used for "add" / GUI reveal)
//   selftest                    availability + timing, no secrets involved
//   clip     --clear-after N    stdin -> pasteboard (ConcealedType), clear after N s if unchanged
//
// Private keys never leave the Secure Enclave. key files hold only the SE-wrapped
// dataRepresentation blob, which is useless on any other machine.

import AppKit
import CryptoKit
import Foundation
import LocalAuthentication
import Security

// First executable startup action: inherited authority must never survive exec.
if fcntl(3, F_GETFD) != -1 && fcntl(3, F_SETFD, FD_CLOEXEC) == -1 {
    fail("caller refused: channel flags")
}
enforceCaller()

struct ProcessIdentity: Equatable {
    let pid: pid_t
    let seconds: UInt64
    let microseconds: UInt64
}

func callerRefused(_ reason: String) -> Never { fail("caller refused: " + reason) }

func canonicalPath(_ path: String) -> String? {
    guard let resolved = realpath(path, nil) else { return nil }
    defer { free(resolved) }
    return String(cString: resolved)
}

func processIdentity(_ pid: pid_t) -> ProcessIdentity {
    var info = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else {
        callerRefused("process identity")
    }
    return ProcessIdentity(pid: pid, seconds: info.pbi_start_tvsec,
                           microseconds: info.pbi_start_tvusec)
}

func enforceCaller() {
    guard let home = getpwuid(getuid())?.pointee.pw_dir else { callerRefused("trust root") }
    var root = String(cString: home) + "/.local/share/karambit/keys"
    #if DEBUG
    if let override = ProcessInfo.processInfo.environment["KARAMBIT_SE_TRUST_ROOT"] { root = override }
    #endif
    guard CommandLine.arguments.filter({ $0 == "--dir" }).count == 1,
          let directory = arg("--dir"), let trusted = canonicalPath(root),
          canonicalPath(directory) == trusted else { callerRefused("key directory not trusted") }

    let parentPID = getppid()
    guard parentPID > 1 else { callerRefused("parent missing") }
    let parent = processIdentity(parentPID)
    var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    guard proc_pidpath(parentPID, &path, UInt32(path.count)) > 0,
          let executable = canonicalPath(String(cString: path)),
          let bytes = try? Data(contentsOf: URL(fileURLWithPath: executable)),
          let pins = try? String(contentsOfFile: trusted + "/daemon.sha256", encoding: .utf8)
    else { callerRefused("parent pin unavailable") }
    let hash = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    guard pins.split(separator: "\n").map({ $0.trimmingCharacters(in: .whitespacesAndNewlines) })
        .contains(hash) else { callerRefused("parent pin mismatch") }

    var peer: pid_t = 0
    var length = socklen_t(MemoryLayout<pid_t>.size)
    guard getsockopt(3, SOL_LOCAL, LOCAL_PEERPID, &peer, &length) == 0,
          length == MemoryLayout<pid_t>.size, peer == parentPID else { callerRefused("channel peer") }
    var timeout = timeval(tv_sec: 2, tv_usec: 0)
    var noSignal: Int32 = 1
    guard setsockopt(3, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
          setsockopt(3, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
          setsockopt(3, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0
    else { callerRefused("channel timeout setup") }
    var nonce = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, nonce.count, &nonce) == errSecSuccess else {
        callerRefused("nonce generation")
    }
    let own = processIdentity(getpid())
    // Bound the whole exchange as well as each blocking socket operation.
    let deadline = DispatchTime.now().uptimeNanoseconds + 2_000_000_000
    func remainingTimeout(_ option: Int32) {
        let now = DispatchTime.now().uptimeNanoseconds
        guard now < deadline else { callerRefused("channel timeout") }
        let remaining = (deadline - now + 999) / 1000
        var timeout = timeval(tv_sec: Int(remaining / 1_000_000), tv_usec: Int32(remaining % 1_000_000))
        guard setsockopt(3, SOL_SOCKET, option, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0
        else { callerRefused("channel timeout setup") }
    }
    nonce.withUnsafeBytes { buffer in
        var offset = 0
        while offset < buffer.count {
            remainingTimeout(SO_SNDTIMEO)
            let n = Darwin.write(3, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
            guard n > 0, DispatchTime.now().uptimeNanoseconds <= deadline else { callerRefused("channel write") }
            offset += n
        }
    }
    var reply = [UInt8](repeating: 0, count: 72)
    reply.withUnsafeMutableBytes { buffer in
        var offset = 0
        while offset < buffer.count {
            remainingTimeout(SO_RCVTIMEO)
            let n = Darwin.read(3, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
            guard n > 0, DispatchTime.now().uptimeNanoseconds <= deadline else { callerRefused("channel read") }
            offset += n
        }
    }
    guard Array(reply[0..<32]) == nonce else { callerRefused("nonce mismatch") }
    func number(_ range: Range<Int>) -> UInt64 {
        reply[range].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }
    guard number(32..<36) == UInt64(own.pid), number(36..<44) == own.seconds,
          number(44..<52) == own.microseconds, number(52..<56) == UInt64(parent.pid),
          number(56..<64) == parent.seconds, number(64..<72) == parent.microseconds
    else { callerRefused("channel identity") }
    guard getppid() == parentPID, processIdentity(parentPID) == parent else {
        callerRefused("parent changed")
    }
}

typealias SEKey = SecureEnclave.P256.KeyAgreement.PrivateKey

// Keys (all SE P-256, never leave this Mac):
//   bio    Touch ID (.biometryCurrentSet), usable only while unlocked
//   open   no prompt, usable only while unlocked           ("Only me" secrets)
//   agent  no prompt, usable while the screen is LOCKED    (agent-enabled secrets, so
//          background agent jobs keep working); still needs one unlock since boot
enum Tier: String, CaseIterable { case bio, open, agent }

struct HelperError: Error { let msg: String }

/// errSecInteractionNotAllowed: the key's accessibility class forbids use right now
/// (screen locked for bio/open keys, or no unlock since boot for the agent key).
let errSecLocked = -25308

func lockedMessage(_ t: Tier) -> String {
    switch t {
    case .agent: return "mac not unlocked since boot: the agent key works only after the first unlock"
    case .open: return "mac is locked: 'Only me' secrets (and agent secrets not yet moved to the lock-safe key) work only while unlocked. Fix for agent-enabled secrets: run `karambit keys upgrade` once"
    case .bio: return "mac is locked: Touch ID secrets need an unlocked Mac, or a lease granted beforehand"
    }
}

/// Map the SE's "not allowed right now" error to a readable one.
func withLockHint<T>(_ t: Tier, _ body: () throws -> T) throws -> T {
    do { return try body() } catch {
        if (error as NSError).code == errSecLocked { throw HelperError(msg: lockedMessage(t)) }
        throw error
    }
}

func emit(_ obj: Any) {
    let data = try! JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write("\n".data(using: .utf8)!)
}

func fail(_ msg: String, code: Int32 = 1) -> Never {
    emit(["error": msg])
    exit(code)
}

func arg(_ name: String) -> String? {
    let a = CommandLine.arguments
    guard let i = a.firstIndex(of: name), i + 1 < a.count else { return nil }
    return a[i + 1]
}

func keyURL(_ dir: String, _ tier: Tier) -> URL {
    URL(fileURLWithPath: dir).appendingPathComponent("\(tier.rawValue).key")
}

func accessControl(_ tier: Tier) throws -> SecAccessControl {
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if tier == .bio { flags.insert(.biometryCurrentSet) }
    let accessible = tier == .agent
        ? kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        : kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    var err: Unmanaged<CFError>?
    guard let ac = SecAccessControlCreateWithFlags(nil, accessible, flags, &err)
    else { throw HelperError(msg: "access control: \(err!.takeRetainedValue())") }
    return ac
}

func loadKey(_ dir: String, _ tier: Tier, _ ctx: LAContext?) throws -> SEKey {
    let data = try Data(contentsOf: keyURL(dir, tier))
    if let ctx { return try SEKey(dataRepresentation: data, authenticationContext: ctx) }
    return try SEKey(dataRepresentation: data)
}

/// One LAContext evaluation -> reused for every bio key operation in this process.
func evaluateBiometry(_ reason: String) throws -> LAContext {
    let ctx = LAContext()
    ctx.localizedCancelTitle = "Deny"
    var err: NSError?
    guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) else {
        throw HelperError(msg: "biometrics unavailable: \(err?.localizedDescription ?? "unknown")")
    }
    let sem = DispatchSemaphore(value: 0)
    var ok = false
    var evalErr: Error?
    ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { s, e in
        ok = s; evalErr = e; sem.signal()
    }
    sem.wait()
    guard ok else { throw HelperError(msg: "touch id denied: \(evalErr?.localizedDescription ?? "unknown")") }
    return ctx
}

// BEGIN TYPED PROMPTS (Foundation-only; exercised without LAContext or SE).
// Each parameter is data, never template text. Arity is part of the wire protocol.
let promptTemplates: [String: (Int, ([String]) -> String)] = [
    "add_source": (6, { "add source \($0[0]) of kind \($0[1]) at \($0[2]); auth \($0[3]); policy SHA-256 prefix \($0[4]); credential: \($0[5])" }),
    "retarget_source": (10, { "retarget source \($0[0]) from kind \($0[1]) at \($0[2]) to kind \($0[3]) at \($0[4]); auth \($0[5]) to \($0[6]); policy SHA-256 prefix \($0[7]) to \($0[8]); credential: \($0[9])" }),
    "remove_source": (6, { "remove source \($0[0]) of kind \($0[1]) at \($0[2]); auth \($0[3]); policy SHA-256 prefix \($0[4]); credential: \($0[5])" }),
    "unlock": (1, { "unlock \($0[0])" }),
    "use": (3, { "use \($0[0]) for \($0[1]), context \($0[2])" }),
    "overwrite": (2, { "overwrite \($0[0]) for \($0[1])" }),
    "add_relaxed": (3, { "add \($0[0]) with Touch ID off for \($0[1]), access \($0[2])" }),
    "change_policy": (2, { "change policy of \($0[0]) for \($0[1])" }),
    "delete": (2, { "delete \($0[0]) for \($0[1])" }),
    "upgrade_keys": (1, { "create the lock-safe agent key if needed and let agents use \($0[0]) while the screen is locked" }),
    "move_agent_key": (0, { _ in "move secrets to the agent key" }),
    "verify_agent_key": (0, { _ in "verify the agent key" }),
    "change_config": (1, { "change Karambit setting \($0[0])" }),
    "recover": (0, { _ in "recover Karambit using the verified paper key" }),
    "retire_keys": (0, { _ in "retire Karambit keys" }),
    "rotate_backup": (2, { "change backup recipient and re-back-up \($0[0]) for \($0[1])" }),
    "rewrap_backup": (2, { "re-back-up \($0[0]) for \($0[1])" }),
    "add_sso_portal": (3, { "add AWS SSO portal \($0[0]) at \($0[1]) in \($0[2])" }),
    "repoint_sso_portal": (3, { "repoint AWS SSO portal \($0[0]) to \($0[1]) in \($0[2])" }),
    "sso_limit": (2, { "let AWS SSO portal \($0[0]) stay signed in \($0[1])" }),
    "sso_decrypt": (0, { _ in "activate AWS SSO profiles" }),
    "grant": (4, { "lease \($0[0]) to \($0[1]) for \($0[2]) hours, scope \($0[3])" }),
    "sso_login": (5, { "sign in to AWS SSO portal \($0[0]) at \($0[1]) and let agents use \($0[2]) of \($0[3]) SSO profiles, renewed \($0[4])" }),
    "sso_register": (1, { "activate AWS SSO profiles \($0[0])" }),
    "sso_use": (3, { "use human-only AWS SSO profile \($0[0]), account \($0[1]), role \($0[2])" }),
    "run_unredacted": (1, { "run \($0[0]) without secret-output redaction" }),
    "repin_helper": (0, { _ in "approve replacement Karambit helpers" }),
    "screen_lock_probe": (0, { _ in "probe screen lock" }),
]

func renderPrompt(_ wire: String) throws -> String {
    guard let data = wire.data(using: .utf8),
          let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(obj.keys) == Set(["id", "params"]),
          let id = obj["id"] as? String,
          let params = obj["params"] as? [String],
          let (arity, render) = promptTemplates[id] else {
        throw HelperError(msg: "invalid prompt identity or fields")
    }
    guard params.count == arity else { throw HelperError(msg: "invalid prompt parameter count") }
    for param in params {
        guard param.unicodeScalars.count <= 120 else { throw HelperError(msg: "prompt parameter too long") }
        guard !param.unicodeScalars.contains(where: {
            $0.value <= 0x1f || (0x7f...0x9f).contains($0.value)
                || (0x200b...0x200f).contains($0.value)
                || (0x2028...0x202e).contains($0.value)
                || (0x2060...0x206f).contains($0.value) || $0.value == 0xfeff || $0.value == 0x061c
        }) else { throw HelperError(msg: "prompt parameter contains control characters") }
    }
    // JSON quoting makes embedded quotes/backslashes unambiguous as parameter data.
    let quoted = try params.map { param -> String in
        let bytes = try JSONSerialization.data(withJSONObject: [param], options: [.withoutEscapingSlashes])
        return String(String(data: bytes, encoding: .utf8)!.dropFirst().dropLast())
    }
    return render(quoted)
}
// END TYPED PROMPTS

// Assigned before dispatch: malformed prompts cannot reach even an Open-key ECDH.
var validatedPrompt: String?
func reasonArg() -> String {
    guard let prompt = validatedPrompt else { fail("typed prompt required") }
    return prompt
}

func dirArg() -> String {
    guard let d = arg("--dir") else { fail("--dir required") }
    return d
}

// MARK: commands

func cmdKeygen() throws {
    let dir = dirArg()
    guard SecureEnclave.isAvailable else { throw HelperError(msg: "secure enclave unavailable") }
    try FileManager.default.createDirectory(
        atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    for t in Tier.allCases where FileManager.default.fileExists(atPath: keyURL(dir, t).path) {
        throw HelperError(msg: "\(t.rawValue).key already exists; refusing to overwrite")
    }
    var out: [String: String] = [:]
    for t in Tier.allCases {
        out[t.rawValue] = try createKey(dir, t)
    }
    emit(out)
}

func createKey(_ dir: String, _ t: Tier) throws -> String {
    let k = try SEKey(accessControl: try accessControl(t))
    let url = keyURL(dir, t)
    guard FileManager.default.createFile(
        atPath: url.path, contents: k.dataRepresentation, attributes: [.posixPermissions: 0o600])
    else { throw HelperError(msg: "write \(url.path) failed") }
    return k.publicKey.x963Representation.base64EncodedString()
}

/// Add the agent key to a vault made before it existed. Never overwrites.
func cmdAddkey() throws {
    let dir = dirArg()
    guard arg("--tier") == Tier.agent.rawValue else { throw HelperError(msg: "addkey: only --tier agent is supported") }
    guard SecureEnclave.isAvailable else { throw HelperError(msg: "secure enclave unavailable") }
    if FileManager.default.fileExists(atPath: keyURL(dir, .agent).path) {
        throw HelperError(msg: "agent.key already exists; refusing to overwrite")
    }
    emit([Tier.agent.rawValue: try createKey(dir, .agent)])
}

func cmdPubkeys() throws {
    let dir = dirArg()
    var out: [String: String] = [:]
    // Loading without an LAContext and reading the public key does not prompt.
    // bio + open are required; agent is optional (older vaults).
    for t in Tier.allCases where t != .agent || FileManager.default.fileExists(atPath: keyURL(dir, t).path) {
        out[t.rawValue] = try loadKey(dir, t, nil).publicKey.x963Representation.base64EncodedString()
    }
    emit(out)
}

func cmdEcdh() throws {
    let dir = dirArg()
    let input = FileHandle.standardInput.readDataToEndOfFile()
    guard let obj = try JSONSerialization.jsonObject(with: input) as? [String: Any],
          let reqs = obj["requests"] as? [[String: String]]
    else { throw HelperError(msg: "bad stdin json") }

    let parsed: [(Tier, P256.KeyAgreement.PublicKey)] = try reqs.map { r in
        guard let ts = r["tier"], let t = Tier(rawValue: ts) else { throw HelperError(msg: "bad tier") }
        guard let b = r["eph"], let d = Data(base64Encoded: b) else { throw HelperError(msg: "bad eph") }
        return (t, try P256.KeyAgreement.PublicKey(x963Representation: d))
    }

    // Single prompt only if at least one bio secret is in the batch.
    let ctx: LAContext? = parsed.contains { $0.0 == .bio } ? try evaluateBiometry(reasonArg()) : nil
    var keys: [Tier: SEKey] = [:]
    var shared: [String] = []
    for (t, eph) in parsed {
        if keys[t] == nil { keys[t] = try withLockHint(t) { try loadKey(dir, t, t == .bio ? ctx : nil) } }
        let s = try withLockHint(t) { try keys[t]!.sharedSecretFromKeyAgreement(with: eph) }
        shared.append(s.withUnsafeBytes { Data($0) }.base64EncodedString())
    }
    ctx?.invalidate()
    emit(["shared": shared])
}

func cmdAuth() throws {
    let ctx = try evaluateBiometry(reasonArg())
    ctx.invalidate()
    emit(["ok": true])
}

func cmdSelftest() {
    var out: [String: Any] = ["secure_enclave": SecureEnclave.isAvailable]
    let ctx = LAContext()
    var err: NSError?
    out["biometrics"] = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
    if let err { out["biometrics_error"] = err.localizedDescription }
    out["biometry_type"] = ctx.biometryType == .touchID ? "touchid" : "\(ctx.biometryType.rawValue)"
    // Throwaway SE key (no biometry) to prove creation + ECDH work on this Mac, and time it.
    do {
        let t0 = Date()
        let k = try SEKey(accessControl: try accessControl(.open))
        let t1 = Date()
        let eph = P256.KeyAgreement.PrivateKey()
        _ = try k.sharedSecretFromKeyAgreement(with: eph.publicKey)
        let t2 = Date()
        out["se_keygen_ms"] = Int((t1.timeIntervalSince(t0)) * 1000)
        out["se_ecdh_ms"] = Int((t2.timeIntervalSince(t1)) * 1000)
    } catch {
        out["se_error"] = "\(error)"
    }
    emit(out)
}

func cmdClip() {
    signal(SIGHUP, SIG_IGN)  // survive the invoking terminal closing
    let secs = max(1, min(600, Int(arg("--clear-after") ?? "30") ?? 30))
    var data = FileHandle.standardInput.readDataToEndOfFile()
    defer { data.resetBytes(in: 0..<data.count) }
    let pb = NSPasteboard.general
    pb.clearContents()
    let item = NSPasteboardItem()
    guard item.setData(data, forType: .string) else { fail("clipboard unavailable") }
    // Marker types honoured by clipboard managers / Universal Clipboard.
    guard item.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")),
          item.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.TransientType")),
          pb.writeObjects([item]) else { fail("clipboard unavailable") }
    let mark = pb.changeCount
    // Detach from the caller so `karambit get --clip` returns immediately.
    emit(["ok": true, "clear_after": secs])
    fflush(stdout)
    close(STDOUT_FILENO)
    Thread.sleep(forTimeInterval: TimeInterval(secs))
    if pb.changeCount == mark { pb.clearContents() }
}

let cmd = CommandLine.arguments.dropFirst().first ?? ""
do {
    if cmd == "auth" || cmd == "ecdh" {
        guard let wire = arg("--prompt"), !CommandLine.arguments.contains("--reason"),
              CommandLine.arguments.filter({ $0 == "--prompt" }).count == 1 else {
            throw HelperError(msg: "one typed prompt required; free-text reasons refused")
        }
        validatedPrompt = try renderPrompt(wire)
    }
    switch cmd {
    #if DEBUG
    case "__probe_fd3": emit(["cloexec": fcntl(3, F_GETFD) & FD_CLOEXEC])
    #endif
    case "keygen": try cmdKeygen()
    case "addkey": try cmdAddkey()
    case "pubkeys": try cmdPubkeys()
    case "ecdh": try cmdEcdh()
    case "auth": try cmdAuth()
    case "selftest": cmdSelftest()
    case "clip": cmdClip()
    default: fail("usage: karambit-se-helper keygen|addkey|pubkeys|ecdh|auth|selftest|clip", code: 2)
    }
} catch let e as HelperError {
    fail(e.msg)
} catch {
    fail("\(error)")
}
