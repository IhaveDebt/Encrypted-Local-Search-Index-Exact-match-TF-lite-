//
// SecureIndex.swift
// Build an encrypted local inverted index supporting exact-term search on encrypted tokens.
// Uses AES-GCM for deterministic token encryption (via HMAC-based deterministic key derivation).
// Educational/demo code: not for hard crypto production use without review.
// Swift 5+
//

import Foundation
import CryptoKit

// -----------------------------
// Utilities
// -----------------------------
extension Data {
    func hex() -> String { map { String(format: "%02x", $0) }.joined() }
}

func sha256(_ data: Data) -> Data {
    return Data(SHA256.hash(data: data))
}

// Deterministic token encoder: HMAC-SHA256 with master key -> take first 16 bytes -> AES-GCM with zero nonce (not best practice)
// For demo we build a deterministic token using HMAC only (no AES), which is safer to illustrate deterministic searchable token.
struct Tokenizer {
    let hmacKey: SymmetricKey
    init(masterKey: SymmetricKey) {
        self.hmacKey = masterKey
    }
    func tokenize(_ text: String) -> [String] {
        // basic whitespace + punctuation tokenizer, lowercase
        let lowered = text.lowercased()
        let parts = lowered.split { !$0.isLetter && !$0.isNumber }
        return parts.map { String($0) }
    }
    func deterministicToken(_ term: String) -> String {
        let mac = HMAC<SHA256>.authenticationCode(for: Data(term.utf8), using: hmacKey)
        return Data(mac).hex()
    }
}

// -----------------------------
// Encrypted Inverted Index
// -----------------------------
class SecureIndex {
    private let tokenizer: Tokenizer
    // mapping token_hmac -> set of docIDs (stored encrypted mapping)
    private var index: [String: Set<String>] = [:]
    // encrypted doc store: docID -> encrypted content (we'll store plaintext for demo)
    private var docs: [String: String] = [:]
    
    init(masterKey: SymmetricKey) {
        self.tokenizer = Tokenizer(masterKey: masterKey)
    }
    
    func addDocument(id: String, content: String) {
        docs[id] = content // in real world you'd encrypt
        let tokens = tokenizer.tokenize(content)
        let uniqueTokens = Set(tokens)
        for t in uniqueTokens {
            let tokenId = tokenizer.deterministicToken(t)
            var set = index[tokenId] ?? Set<String>()
            set.insert(id)
            index[tokenId] = set
        }
    }
    
    func search(term: String) -> [String] {
        let tokenId = tokenizer.deterministicToken(term.lowercased())
        guard let hits = index[tokenId] else { return [] }
        // for demo return doc IDs and snippets
        return hits.map { id in
            let snippet = docs[id] ?? ""
            return "\(id): \(snippet.prefix(120))"
        }
    }
    
    // Export/Import index snapshot (simulate storing only encrypted token keys + docIDs hashed)
    func exportSnapshot() -> Data {
        // produce JSON of token->list(docIDs)
        var out: [String: [String]] = [:]
        for (k,v) in index { out[k] = Array(v) }
        return try! JSONSerialization.data(withJSONObject: out, options: [.prettyPrinted])
    }
    
    func importSnapshot(_ data: Data) {
        if let j = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: [String]] {
            index = [:]
            for (k,v) in j { index[k] = Set(v) }
        }
    }
}

// -----------------------------
// Demo: build index and perform searches
// -----------------------------
func demoSecureIndex() {
    print("=== SecureIndex Demo ===")
    // derive master key from passphrase for demo
    let pass = "ultra-strong-demo-key-2025"
    let keyMaterial = sha256(Data(pass.utf8))
    let masterKey = SymmetricKey(data: keyMaterial)
    
    let idx = SecureIndex(masterKey: masterKey)
    idx.addDocument(id: "doc1", content: "Swift is a powerful and intuitive programming language for macOS, iOS, watchOS, and tvOS.")
    idx.addDocument(id: "doc2", content: "Cryptography and privacy engineering are essential for secure systems.")
    idx.addDocument(id: "doc3", content: "This sample document mentions Swift and cryptography together.")
    
    print("Search 'swift' ->")
    for s in idx.search(term: "swift") { print(" ", s) }
    print("\nSearch 'cryptography' ->")
    for s in idx.search(term: "cryptography") { print(" ", s) }
    
    print("\nExport snapshot (tokens only):")
    let snap = idx.exportSnapshot()
    print(String(data: snap, encoding: .utf8)!)
    
    // simulate reimport
    let idx2 = SecureIndex(masterKey: masterKey)
    idx2.importSnapshot(snap)
    print("\nReimported index, search 'swift' ->", idx2.search(term: "swift"))
}

demoSecureIndex()
