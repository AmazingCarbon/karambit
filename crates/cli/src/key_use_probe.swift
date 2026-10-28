// Standalone key-use probe for `karambit doctor --agent-env` (row `key-blob-use`).
//
// NOT the production helper, and it never talks to Karambit. It answers one question: can an
// ordinary process in this environment create and then RELOAD a no-prompt Secure Enclave key from
// nothing but a blob file, and use it? (Known limit #6.) Everything is synthetic.
//
// usage: key_use_probe <scratch-dir>
//   stdout (exactly one token, newline-terminated):
//     match        the reloaded key agreed with an ephemeral software peer (key use is possible)
//     mismatch     both sides produced a shared secret, but they differ
//     unavailable  no Secure Enclave on this host (exit status 3)
//   any other failure: no stdout, non-zero exit status, details on stderr (never secret bytes).
//
// Creates:  one file, <scratch-dir>/probe-key.blob (0600, O_EXCL), holding the synthetic key blob.
// Reads:    only that file, through the descriptor that created it (never by pathname).
// Removes:  that file, on every path out of run().
// Key policy: the access control CryptoKit applies by default (private-key-usage only), no
//           user-presence or biometric flags, so there is never a prompt. No system credential
//           store is written: the blob file is the only artifact of the key.

import CryptoKit
import Foundation

let blobName = "probe-key.blob"

func createBlob(at path: String) throws -> Int32 {
    let key = try SecureEnclave.P256.KeyAgreement.PrivateKey()
    // O_EXCL|O_NOFOLLOW: only a file this process created is ever written. The descriptor is kept
    // open and the blob is read back through it, never by reopening the pathname, so a file or
    // symlink swapped into the path afterwards is never read.
    let fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
    if fd < 0 { throw CocoaError(.fileWriteUnknown) }
    do {
        try FileHandle(fileDescriptor: fd, closeOnDealloc: false).write(contentsOf: key.dataRepresentation)
    } catch {
        close(fd)
        unlink(path)
        throw error
    }
    return fd
}

func run(scratch: String) -> Int32 {
    guard SecureEnclave.isAvailable else {
        print("unavailable")
        return 3
    }
    let path = scratch + "/" + blobName
    let fd: Int32
    do {
        // The key object from createBlob is gone once it returns: what is used below exists
        // only as the blob file plus this process.
        fd = try createBlob(at: path)
    } catch {
        FileHandle.standardError.write(Data("create: \(error)\n".utf8))
        return 1
    }
    defer {
        close(fd)
        unlink(path)
    }
    do {
        guard lseek(fd, 0, SEEK_SET) == 0 else { return 1 }
        guard let blob = try FileHandle(fileDescriptor: fd, closeOnDealloc: false).readToEnd() else { return 1 }
        let reloaded = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
        let peer = P256.KeyAgreement.PrivateKey()
        let seSide = try reloaded.sharedSecretFromKeyAgreement(with: peer.publicKey)
        let peerSide = try peer.sharedSecretFromKeyAgreement(with: reloaded.publicKey)
        let a = seSide.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(), sharedInfo: Data(), outputByteCount: 32)
        let b = peerSide.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(), sharedInfo: Data(), outputByteCount: 32)
        print(a == b ? "match" : "mismatch")
        return 0
    } catch {
        FileHandle.standardError.write(Data("use: \(error)\n".utf8))
        return 1
    }
}

guard CommandLine.arguments.count == 2 else { exit(2) }
exit(run(scratch: CommandLine.arguments[1]))
