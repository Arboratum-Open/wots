# Winternitz One Time Signature+ Scheme

Winternitz One Time Signature Scheme (W-OTS+) in Rust as demenstrated in [IETF RFC 8391](https://datatracker.ietf.org/doc/rfc8391/). The implementation should support different parameter combinations but this only contain default one for now. I'm planning to expand them in the future. Despite it's called W-OTS and described as W-OTS+ varaint which first mentioned in[1]. This is acutally standalone version of WOTS-T scheme[2] which solve potentail issue of W-OTS+ from multi-target attacks. The RFC still refers as W-OST+.

### Reference

[1] Hülsing, Andreas. "W-OTS+–shorter signatures for hash-based signature schemes." International Conference on Cryptology in Africa. Springer, Berlin, Heidelberg, 2013.

[2] Hülsing, Andreas, Joost Rijneveld, and Fang Song. "Mitigating multi-target attacks in hash-based signatures." Public-Key Cryptography–PKC 2016. Springer, Berlin, Heidelberg, 2016. 387-416.