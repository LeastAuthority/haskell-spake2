{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE NamedFieldPuns #-}

{-|
Module: Crypto.Spake2
Description: Implementation of SPAKE2 key exchange protocol

Say that you and someone else share a secret password, and you want to use
this password to arrange some secure channel of communication. You want:

 * to know that the other party also knows the secret password (maybe
   they're an imposter!)
 * the password to be secure against offline dictionary attacks
 * probably some other things

SPAKE2 is an algorithm for agreeing on a key exchange that meets these
criteria. See [Simple Password-Based Encrypted Key Exchange
Protocols](http://www.di.ens.fr/~pointche/Documents/Papers/2005_rsa.pdf) by
Michel Abdalla and David Pointcheval for more details.

== How it works

=== Preliminaries

Let's say we have two users, user A and user B. They have already agreed on
the following public information:

 * cyclic group, \(G\) of prime order, \(p\)
 * generating element \(g \in G\), such that \(g \neq 1\)
 * hash algorithm to use, \(H\)

__XXX__: jml's current understanding is that all of this is provided by something
like 'Crypto.ECC.Curve_X25519', and generally anything that implements the
'Crypto.ECC.EllipticCurve' typeclass in a sane way. It is possible that this
typeclass is insufficient.

If the connection is asymmetric (e.g. if user A is a client and user B is a
server), then they will also have:

 * two arbitrary elements in \(M, N \in G\), where \(M\) is associated with
   user A and \(N\) with user B.

If the connection is symmetric (e.g. if user A and B are arbitrary peers),
then they will instead have:

 * a single arbitrary element \(S \in G\)

__XXX__: jml's current understanding is that these are indeed arbitrarily chosen,
and are part of the SPAKE2 protocol specialised to a particular use case. i.e.
that these are /not/ provided by 'EllipticCurve' or the like.

And, they also have a secret password, which in theory is an arbitrary bit
string, but for the purposes of this module is an arbitrary /byte/ string.

This password is mapped to a /scalar/ in group \(G\), in a way that's mutually
agreed to both parties. The means of mapping may be public, but the actual
mapped value /must/ be secret.

=== Definitions

__NOTE__: This is jml's best understanding. It's likely to be wrong.

[@scalar@]: a number between 0 and \(p\) (that is, in \(\mathbb{Z}_{p}\)).

[@point@]: a member of the group, \(G\).

[@addition@]: the binary operation on points in the group \(G\). Confusingly,
literature often writes this using product notation.

[@scalar multiplication@]: adding a point to itself a scalar number of times.
Confusingly, this is often written as \(X^{n}\) where \(X\) is a point and \(n\)
a scalar.

#protocol#

=== Protocol

==== How we map the password to a scalar

TODO

==== How we exchange information

/This is derived from the paper linked above./

One side, A, initiates the exchange. They draw a random scalar, \(x\), and
matching point, \(X\), from the group. They then "blind" \(X\) by adding it to \(M\)
multiplied by the password in scalar form. Call this \(X^{\star}\).

\[X^{\star} \leftarrow X \cdot M^{pw}\]

to the other side, side B.

Side B does the same thing, except they use \(N\) instead of \(M\) to blind
the result, and they call it \(Y\) instead of \(X\).

\[Y^{\star} \leftarrow Y \cdot N^{pw}\]

After side A receives \(Y^{\star}\), it calculates \(K_A\), which is the last
missing input in calculating the session key.

\[K_A \leftarrow (Y^{\star}/N^{pw})^x\]

That is, \(K_A\) is \(Y^{\star}\) subtracted from \(N\) scalar multiplied by
\(pw\), all of which is scalar multiplied by \(x\).

Side B likewise calculates:

\[K_B \leftarrow (X^{\star}/M^{pw})^y\]

They then both figure out the session key:

\[SK \leftarrow H(A, B, X^{\star}, Y^{\star}, K, pw)\]

Where side A uses \(K_A\) and side B uses \(K_B\). Including \(pw\) in the
session key is what makes this SPAKE2, not SPAKE1.

If both parties were honest and knew the password, the key will be the same on
both sides.

==== How python-spake2 works

- Message to other side is prepended with a single character, @A@, @B@, or
  @S@, to indicate which side it came from
- The hash function for generating the session key has a few interesting properties:
    - uses SHA256 for hashing
    - does not include password or IDs directly, but rather uses /their/ SHA256
      digests as inputs to the hash
    - for the symmetric version, it sorts \(X^{\star}\) and \(Y^{\star}\),
      because neither side knows which is which
- By default, the ID of either side is the empty bytestring

Hopefully the same as what was written above. Open questions:

- what's up with its obsession in padding things out to a certain number of bytes
- are we sure we're using the same hash algorithm, "blinds"

== Assumptions

* 'curveGenerateKeyPair' generates a point and scalar that we can use in the SPAKE2 protocol
* 'EllipticCurveArith' provides all the operations we need to implement SPAKE2
* We can reasonably implement 'EllipticCurveArith' for "ed25519" so as to match python-spake2's default SPAKE2 protocol parameters.

== References

* [Javascript implementation](https://github.com/bitwiseshiftleft/sjcl/pull/273/), includes long, possibly relevant discussion
* [Python implementation](https://github.com/warner/python-spake2)
* [SPAKE2 random elements](http://www.lothar.com/blog/54-spake2-random-elements/) - blog post by warner about choosing \(M\) and \(N\)
* [Simple Password-Based Encrypted Key Exchange Protocols](http://www.di.ens.fr/~pointche/Documents/Papers/2005_rsa.pdf) by Michel Abdalla and David Pointcheval
* [draft-irtf-cfrg-spake2-03](https://tools.ietf.org/html/draft-irtf-cfrg-spake2-03) - expired IRTF draft for SPAKE2

-}

module Crypto.Spake2
  ( something
  , Password
  , expandPassword
  ) where

import Protolude

import Data.ByteArray (ByteArray, ByteArrayAccess)

import Crypto.Spake2.Groups (expandData)


something :: a -> a
something x = x

-- | Shared secret password used to negotiate the connection.
newtype Password = Password ByteString

expandPassword :: (ByteArrayAccess bytes, ByteArray output) => Password -> Int -> output
expandPassword (Password bytes) numBytes = expandData "SPAKE2 password" bytes numBytes
