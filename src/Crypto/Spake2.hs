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

#protocol#

=== Protocol

==== How we map the password to a scalar

TODO

==== How we exchange information

/This is derived from the paper linked above./

One side, A, initiates the exchange. They draw a random scalar, \(x\), and
matching element, \(X\), from the group. They then "blind" \(X\) by adding it to \(M\)
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

== Open questions

* how are blinded elements turned into bytes to be sent on the wire?
  * how does this relate to establish \(M\), \(N\), and \(S\)
  * does this correspond to 'encodeElement'?

* how are bytes translated back into blinded elements?
  * does this correspond to 'decodeElement'?
* how is the password (a bytestring) turned into a scalar
  * Using HKDF expansion to a length (in bytes) determined by the group, \(n\) + 16
  * What is the relationship between \(n\) and the group?
  * Where does the 16 come from?
  * this cannot correspond to 'decodeElement',
    because there is no way to recover a scalar from a element.
    * Surely it ought to match the way we encode everything else?
    * Is this a sign that the 'EllipticCurveArith' interface isn't what we want?
    * Worse, is it a sign that the underlying implementations aren't what we want?
* how do we determine \(M\), \(N\), \(S\)?
  * does there need to be a well-known, agreed-upon way of turning simple bytestrings into group elements?
  * does this mechanism need to vary by group, or can it be defined in general terms?
* how does endianness come into play?
* what is Shallue-Woestijne-Ulas and why is it relevant?

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
  , makePassword
  -- * The SPAKE2 protocol
  , Protocol
  , makeAsymmetricProtocol
  , makeSymmetricProtocol
  , startSpake2
  , Math.computeOutboundMessage
  , Math.generateKeyMaterial
  , extractElement
  , MessageError
  , formatError
  , elementToMessage
  , createSessionKey
  , SideID(..)
  , WhichSide(..)
  ) where

import Protolude hiding (group)

import Crypto.Error (CryptoError, CryptoFailable(..))
import Crypto.Hash (HashAlgorithm, hashWith)
import Crypto.Random.Types (MonadRandom(..))
import Data.ByteArray (ByteArray, ByteArrayAccess)
import qualified Data.ByteString as ByteString

import Crypto.Spake2.Groups (Group(..), decodeScalar, expandData, scalarSizeBytes)
import qualified Crypto.Spake2.Math as Math


-- | Do-nothing function so that we have something to import in our tests.
-- TODO: Actually test something genuine and then remove this.
something :: a -> a
something x = x

-- | Shared secret password used to negotiate the connection.
--
-- Constructor deliberately not exported,
-- so that once a 'Password' has been created, the actual password cannot be retrieved by other modules.
--
-- Construct with 'makePassword'.
newtype Password = Password ByteString deriving (Eq, Ord)

-- | Construct a password.
makePassword :: ByteString -> Password
makePassword = Password

-- | Bytes that identify a side of the protocol
newtype SideID = SideID { unSideID :: ByteString } deriving (Eq, Ord, Show)

-- | Convert a user-supplied password into a scalar on a group.
passwordToScalar :: Group group => group -> Password -> Scalar group
passwordToScalar group password =
  let oversized = expandPassword password (scalarSizeBytes group + 16) :: ByteString
  in decodeScalar group oversized

-- | Expand a password using HKDF so that it has a certain number of bytes.
--
-- TODO: jml cannot remember why you might want to call this.
expandPassword :: ByteArray output => Password -> Int -> output
expandPassword (Password bytes) numBytes = expandData info bytes numBytes
  where
    -- This needs to be exactly "SPAKE2 pw"
    -- See <https://github.com/bitwiseshiftleft/sjcl/pull/273/#issuecomment-185251593>
    info = "SPAKE2 pw"

-- | Turn an element into a message from this side of the protocol.
elementToMessage :: Group group => Protocol group hashAlgorithm -> Element group -> ByteString
elementToMessage protocol element = prefix <> encodeElement (group protocol) element
  where
    prefix =
      case relation protocol of
        Symmetric _ -> "S"
        Asymmetric{us=SideA} -> "A"
        Asymmetric{us=SideB} -> "B"


data MessageError
  = EmptyMessage
  | UnexpectedPrefix Word8 Word8
  | BadCrypto CryptoError ByteString
  deriving (Eq, Show)

formatError :: MessageError -> Text
formatError EmptyMessage = "Other side sent us an empty message"
formatError (UnexpectedPrefix got expected) = "Other side claims to be " <> show (chr (fromIntegral got)) <> ", expected " <> show (chr (fromIntegral expected))
formatError (BadCrypto err message) = "Could not decode message (" <> show message <> ") to element: " <> show err

-- | Extract an element on the group from an incoming message.
--
-- Returns a 'MessageError' if we cannot decode the message,
-- or the other side does not appear to be the expected other side.
--
-- TODO: Need to protect against reflection attack at some point.
extractElement :: Group group => Protocol group hashAlgorithm -> ByteString -> Either MessageError (Element group)
extractElement protocol message =
  case ByteString.uncons message of
    Nothing -> throwError EmptyMessage
    Just (prefix, msg)
      | prefix /= theirPrefix (relation protocol) -> throwError $ UnexpectedPrefix prefix (theirPrefix (relation protocol))
      | otherwise ->
        case decodeElement (group protocol) msg of
          CryptoFailed err -> throwError (BadCrypto err msg)
          CryptoPassed element -> pure element


-- | One side of the SPAKE2 protocol.
data Side group
  = Side
  { sideID :: SideID -- ^ Bytes identifying this side
  , blind :: Element group -- ^ Arbitrarily chosen element in the group
                           -- used by this side to blind outgoing messages.
  }

-- | Which side we are.
data WhichSide = SideA | SideB deriving (Eq, Ord, Show, Bounded, Enum)

-- | Relation between two sides in SPAKE2.
-- Can be either symmetric (both sides are the same), or asymmetric.
--
-- XXX: Maybe too generic? Could reasonably replace 'a' with 'Side group'.
data Relation a
  = Asymmetric
  { sideA :: a -- ^ Side A. Both sides need to agree who side A is.
  , sideB :: a -- ^ Side B. Both sides need to agree who side B is.
  , us :: WhichSide -- ^ Which side we are
  }
  | Symmetric
  { bothSides :: a -- ^ Description used by both sides.
  }

theirPrefix :: Relation a -> Word8
theirPrefix relation =
  fromIntegral . ord $ case relation of
                         Asymmetric{us=SideA} -> 'B'
                         Asymmetric{us=SideB} -> 'A'
                         Symmetric{} -> 'S'

-- | Everything required for the SPAKE2 protocol.
--
-- Both sides must agree on these values for the protocol to work.
-- This /mostly/ means value equality, except for 'us', where each side must have complementary (sp?) values.
--
-- Construct with 'makeAsymmetricProtocol' or 'makeSymmetricProtocol'.
data Protocol group hashAlgorithm
  = Protocol
  { group :: group -- ^ The group to use for encryption
  , hashAlgorithm :: hashAlgorithm -- ^ Hash algorithm used for generating the session key
  , relation :: Relation (Side group)  -- ^ How the two sides relate to each other
  }

-- | Construct an asymmetric SPAKE2 protocol.
makeAsymmetricProtocol :: hashAlgorithm -> group -> Element group -> Element group -> SideID -> SideID -> WhichSide -> Protocol group hashAlgorithm
makeAsymmetricProtocol hashAlgorithm group blindA blindB sideA sideB whichSide =
  Protocol
  { group = group
  , hashAlgorithm = hashAlgorithm
  , relation = Asymmetric
               { sideA = Side { sideID = sideA, blind = blindA }
               , sideB = Side { sideID = sideB, blind = blindB }
               , us = whichSide
               }
  }

-- | Construct a symmetric SPAKE2 protocol.
makeSymmetricProtocol :: hashAlgorithm -> group -> Element group -> SideID -> Protocol group hashAlgorithm
makeSymmetricProtocol hashAlgorithm group blind id =
  Protocol
  { group = group
  , hashAlgorithm = hashAlgorithm
  , relation = Symmetric Side { sideID = id, blind = blind }
  }

-- | Get the parameters for the mathematical part of SPAKE2 from the protocol specification.
getParams :: Protocol group hashAlgorithm -> Math.Params group
getParams Protocol{group, relation} =
  case relation of
    Symmetric{bothSides} -> mkParams bothSides bothSides
    Asymmetric{sideA, sideB, us} ->
      case us of
        SideA -> mkParams sideA sideB
        SideB -> mkParams sideB sideA

  where
    mkParams ours theirs =
      Math.Params
      { Math.group = group
      , Math.ourBlind = blind ours
      , Math.theirBlind = blind theirs
      }

startSpake2
  :: (MonadRandom randomly, Group group)
  => Protocol group hashAlgorithm
  -> Password
  -> randomly (Math.Spake2Exchange group)
startSpake2 protocol password =
  Math.startSpake2 Math.Spake2 { Math.params = getParams protocol
                               , Math.password = passwordToScalar (group protocol) password
                               }

-- | Create a session key based on the output of SPAKE2.
createSessionKey
  :: (Group group, HashAlgorithm hashAlgorithm)
  => Protocol group hashAlgorithm  -- ^ The protocol used for this exchange
  -> Element group  -- ^ The message from side A, \(X^{\star}\), or either side if symmetric
  -> Element group  -- ^ The message from side B, \(Y^{\star}\), or either side if symmetric
  -> Element group  -- ^ The calculated key material, \(K\)
  -> Password  -- ^ The shared secret password
  -> ByteString  -- ^ A session key to use for further communication
createSessionKey Protocol{group, hashAlgorithm, relation} x y k (Password password) =
  hashDigest transcript

  where
    hashDigest :: ByteArrayAccess input => input -> ByteString
    hashDigest thing = show (hashWith hashAlgorithm thing)

    transcript =
      case relation of
        Asymmetric{sideA, sideB} -> mconcat [ hashDigest password
                                            , hashDigest (unSideID (sideID sideA))
                                            , hashDigest (unSideID (sideID sideB))
                                            , encodeElement group x
                                            , encodeElement group y
                                            , encodeElement group k
                                            ]
        Symmetric{bothSides} -> mconcat [ hashDigest password
                                        , hashDigest (unSideID (sideID bothSides))
                                        , symmetricElements
                                        , encodeElement group k
                                        ]

    symmetricElements =
      let [ firstMessage, secondMessage ] = sort [ encodeElement group x, encodeElement group y ]
      in firstMessage <> secondMessage
