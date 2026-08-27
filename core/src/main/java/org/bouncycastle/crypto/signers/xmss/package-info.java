/**
 * Engine for XMSS and the XMSS^MT multi-tree variant per RFC 8391 (hash-based stateful
 * signatures), with the SP 800-208 parameter sets. The classes here are the operations the key
 * parameter classes in {@link org.bouncycastle.crypto.params} and the key pair generators in
 * {@link org.bouncycastle.crypto.generators} are built on - WOTS+, the hash addressing scheme,
 * the keyed hash functions, the BDS authentication-path traversal state and the signature
 * structures. They are implementation detail and no compatibility is promised for them.
 * Applications sign and verify through {@link org.bouncycastle.crypto.signers.XMSSSigner} /
 * {@link org.bouncycastle.crypto.signers.XMSSMTSigner}.
 */
package org.bouncycastle.crypto.signers.xmss;
