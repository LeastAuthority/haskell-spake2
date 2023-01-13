{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE NamedFieldPuns #-}

{- |
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

Before exchanging, two nodes need to agree on the following, out-of-band:

In general:

* hash algorithm, \(H\)
* group to use, \(G\)
* arbitrary members of group to use for blinding
* a means of converting this password to a scalar of group

For a specific exchange:

* whether the connection is symmetric or asymmetric
* the IDs of the respective sides
* a shared, secret password in bytes

#protocol#

=== Protocol

==== How we map the password to a scalar

Use HKDF expansion (see 'expandData') to expand the password by 16 bytes,
using an empty salt, and "SPAKE2 pw" as the info.

Then, use a group-specific mapping from bytes to scalars.
Since scalars are normally isomorphic to integers,
this will normally be a matter of converting the bytes to an integer
using standard deserialization
and then turning the integer into a scalar.

==== How we exchange information

See 'Crypto.Spake2.Math' for details on the mathematics of the exchange.

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
    ( Password
    , makePassword

      -- * The SPAKE2 protocol
    , Protocol
    , makeAsymmetricProtocol
    , makeSymmetricProtocol
    , spake2Exchange
    , startSpake2
    , Math.computeOutboundMessage
    , Math.generateKeyMaterial
    , extractElement
    , MessageError
    , formatError
    , elementToMessage
    , createSessionKey
    , SideID (..)
    , WhichSide (..)
    ) where

import Protolude hiding (group)

import Crypto.Error (CryptoError, CryptoFailable (..))
import Crypto.Hash (HashAlgorithm, hashWith)
import Crypto.Random.Types (MonadRandom (..))
import Data.ByteArray (ByteArrayAccess)
import qualified Data.ByteArray as ByteArray
import qualified Data.ByteString as ByteString

import Crypto.Spake2.Group (AbelianGroup (..), Group (..), decodeScalar, scalarSizeBytes)
import qualified Crypto.Spake2.Math as Math
import Crypto.Spake2.Util (expandData)

{- | Shared secret password used to negotiate the connection.

 Constructor deliberately not exported,
 so that once a 'Password' has been created, the actual password cannot be retrieved by other modules.

 Construct with 'makePassword'.
-}
newtype Password = Password ByteString deriving (Eq, Ord)

-- | Construct a password.
makePassword :: ByteString -> Password
makePassword = Password

-- | Bytes that identify a side of the protocol
newtype SideID = SideID {unSideID :: ByteString} deriving (Eq, Ord, Show)

-- | Convert a user-supplied password into a scalar on a group.
passwordToScalar :: AbelianGroup group => group -> Password -> Scalar group
passwordToScalar group password =
    decodeScalar group oversized
  where
    oversized = expandPassword password (scalarSizeBytes group + 16) :: ByteString
    expandPassword (Password bytes) = expandData info bytes
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
            Asymmetric{us = SideA} -> "A"
            Asymmetric{us = SideB} -> "B"

-- | An error that occurs when interpreting messages from the other side of the exchange.
data MessageError e
    = -- | We received an empty bytestring.
      EmptyMessage
    | -- | The bytestring had an unexpected prefix.
      -- We expect the prefix to be @A@ if the other side is side A,
      -- @B@ if they are side B,
      -- or @S@ if the connection is symmetric.
      -- First argument is received prefix, second is expected.
      UnexpectedPrefix Word8 Word8
    | -- | Message could not be decoded to an element of the group.
      -- This can indicate either an error in serialization logic,
      -- or in mathematics.
      BadCrypto CryptoError ByteString
    | -- | An error arising from the "receive" action in 'spake2Exchange'.
      -- Since 0.4.0
      UnknownError e
    deriving (Eq, Show)

-- | Turn a 'MessageError' into human-readable text.
formatError :: Show e => MessageError e -> Text
formatError EmptyMessage = "Other side sent us an empty message"
formatError (UnexpectedPrefix got expected) = "Other side claims to be " <> show (chr (fromIntegral got)) <> ", expected " <> show (chr (fromIntegral expected))
formatError (BadCrypto err message) = "Could not decode message (" <> show message <> ") to element: " <> show err
formatError (UnknownError err) = "Error receiving message from other side: " <> show err

{- | Extract an element on the group from an incoming message.

 Returns a 'MessageError' if we cannot decode the message,
 or the other side does not appear to be the expected other side.

 TODO: Need to protect against reflection attack at some point.
-}
extractElement :: Group group => Protocol group hashAlgorithm -> ByteString -> Either (MessageError error) (Element group)
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
data Side group = Side
    { sideID :: SideID
    -- ^ Bytes identifying this side
    , blind :: Element group
    -- ^ Arbitrarily chosen element in the group
    -- used by this side to blind outgoing messages.
    }

-- | Which side we are.
data WhichSide = SideA | SideB deriving (Eq, Ord, Show, Bounded, Enum)

{- | Relation between two sides in SPAKE2.
 Can be either symmetric (both sides are the same), or asymmetric.
-}
data Relation group
    = Asymmetric
        { sideA :: Side group
        -- ^ Side A. Both sides need to agree who side A is.
        , sideB :: Side group
        -- ^ Side B. Both sides need to agree who side B is.
        , us :: WhichSide
        -- ^ Which side we are
        }
    | Symmetric
        { bothSides :: Side group
        -- ^ Description used by both sides.
        }

theirPrefix :: Relation a -> Word8
theirPrefix relation =
    fromIntegral . ord $ case relation of
        Asymmetric{us = SideA} -> 'B'
        Asymmetric{us = SideB} -> 'A'
        Symmetric{} -> 'S'

{- | Everything required for the SPAKE2 protocol.

 Both sides must agree on these values for the protocol to work.
 This /mostly/ means value equality, except for 'Relation.us',
 where each side must have complementary values.

 Construct with 'makeAsymmetricProtocol' or 'makeSymmetricProtocol'.
-}
data Protocol group hashAlgorithm = Protocol
    { group :: group
    -- ^ The group to use for encryption
    , hashAlgorithm :: hashAlgorithm
    -- ^ Hash algorithm used for generating the session key
    , relation :: Relation group
    -- ^ How the two sides relate to each other
    }

-- | Construct an asymmetric SPAKE2 protocol.
makeAsymmetricProtocol :: hashAlgorithm -> group -> Element group -> Element group -> SideID -> SideID -> WhichSide -> Protocol group hashAlgorithm
makeAsymmetricProtocol hashAlgorithm group blindA blindB sideA sideB whichSide =
    Protocol
        { group = group
        , hashAlgorithm = hashAlgorithm
        , relation =
            Asymmetric
                { sideA = Side{sideID = sideA, blind = blindA}
                , sideB = Side{sideID = sideB, blind = blindB}
                , us = whichSide
                }
        }

-- | Construct a symmetric SPAKE2 protocol.
makeSymmetricProtocol :: hashAlgorithm -> group -> Element group -> SideID -> Protocol group hashAlgorithm
makeSymmetricProtocol hashAlgorithm group blind id =
    Protocol
        { group = group
        , hashAlgorithm = hashAlgorithm
        , relation = Symmetric Side{sideID = id, blind = blind}
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

{- | Perform an entire SPAKE2 exchange.

 Given a SPAKE2 protocol that has all of the parameters for this exchange,
 generate a one-off message from this side and receive a one off message
 from the other.

 Once we are done, return a key shared between both sides for a single
 session.

 Note: as per the SPAKE2 definition, the session key is not guaranteed
 to actually /work/. If the other side has failed to authenticate, you will
 still get a session key. Therefore, you must exchange some other message
 that has been encrypted using this key in order to confirm that the session
 key is indeed shared.

 Note: the "send" and "receive" actions are performed 'concurrently'. If you
 have ordering requirements, consider using a 'TVar' or 'MVar' to coordinate,
 or implementing your own equivalent of 'spake2Exchange'.

 If the message received from the other side cannot be parsed, return a
 'MessageError'.

 Since 0.4.0.
-}
spake2Exchange
    :: (AbelianGroup group, HashAlgorithm hashAlgorithm)
    => Protocol group hashAlgorithm
    -- ^ A 'Protocol' with all the parameters for the exchange. These parameters
    -- must be shared by both sides. Construct with 'makeAsymmetricProtocol' or
    -- 'makeSymmetricProtocol'.
    -> Password
    -- ^ The password shared between both sides. Construct with 'makePassword'.
    -> (ByteString -> IO ())
    -- ^ An action to send a message. The 'ByteString' parameter is this side's
    -- SPAKE2 element, encoded using the group encoding, prefixed according to
    -- the parameters in the 'Protocol'.
    -> IO (Either error ByteString)
    -- ^ An action to receive a message. The 'ByteString' generated ought to be
    -- the protocol-prefixed, group-encoded version of the other side's SPAKE2
    -- element.
    -> IO (Either (MessageError error) ByteString)
    -- ^ Either the shared session key or an error indicating we couldn't parse
    -- the other side's message.
spake2Exchange protocol password send receive = do
    exchange <- startSpake2 protocol password
    let outboundElement = Math.computeOutboundMessage exchange
    let outboundMessage = elementToMessage protocol outboundElement
    (_, inboundMessage) <- concurrently (send outboundMessage) receive
    pure $ do
        inboundMessage' <- first UnknownError inboundMessage
        inboundElement <- extractElement protocol inboundMessage'
        let keyMaterial = Math.generateKeyMaterial exchange inboundElement
        pure (createSessionKey protocol inboundElement outboundElement keyMaterial password)

-- | Commence a SPAKE2 exchange.
startSpake2
    :: (MonadRandom randomly, AbelianGroup group)
    => Protocol group hashAlgorithm
    -> Password
    -> randomly (Math.Spake2Exchange group)
startSpake2 protocol password =
    Math.startSpake2
        Math.Spake2
            { Math.params = getParams protocol
            , Math.password = passwordToScalar (group protocol) password
            }

{- | Create a session key based on the output of SPAKE2.

 \[SK \leftarrow H(A, B, X^{\star}, Y^{\star}, K, pw)\]

 Including \(pw\) in the session key is what makes this SPAKE2, not SPAKE1.

 __Note__: In spake2 0.3 and earlier, The \(X^{\star}\) and \(Y^{\star}\)
 were expected to be from side A and side B respectively. Since spake2 0.4,
 they are the outbound and inbound elements respectively. This fixes an
 interoperability concern with the Python library, and reduces the burden on
 the caller. Apologies for the possibly breaking change to any users of
 older versions of spake2.
-}
createSessionKey
    :: (Group group, HashAlgorithm hashAlgorithm)
    => Protocol group hashAlgorithm
    -- ^ The protocol used for this exchange
    -> Element group
    -- ^ The outbound message, generated by this, \(X^{\star}\), or either side if symmetric
    -> Element group
    -- ^ The inbound message, generated by the other side, \(Y^{\star}\), or either side if symmetric
    -> Element group
    -- ^ The calculated key material, \(K\)
    -> Password
    -- ^ The shared secret password
    -> ByteString
    -- ^ A session key to use for further communication
createSessionKey Protocol{group, hashAlgorithm, relation} outbound inbound k (Password password) =
    hashDigest transcript
  where
    -- The protocol expects that when we include the hash of various
    -- components (e.g. the password) as input for the session key hash,
    -- that we use the *byte* representation of these elements.
    hashDigest :: ByteArrayAccess input => input -> ByteString
    hashDigest thing = ByteArray.convert (hashWith hashAlgorithm thing)

    transcript =
        case relation of
            Asymmetric{sideA, sideB, us} ->
                let (x, y) = case us of
                        SideA -> (inbound, outbound)
                        SideB -> (outbound, inbound)
                 in mconcat
                        [ hashDigest password
                        , hashDigest (unSideID (sideID sideA))
                        , hashDigest (unSideID (sideID sideB))
                        , encodeElement group x
                        , encodeElement group y
                        , encodeElement group k
                        ]
            Symmetric{bothSides} ->
                mconcat
                    [ hashDigest password
                    , hashDigest (unSideID (sideID bothSides))
                    , symmetricElements
                    , encodeElement group k
                    ]

    symmetricElements =
        let [firstMessage, secondMessage] = sort [encodeElement group inbound, encodeElement group outbound]
         in firstMessage <> secondMessage
