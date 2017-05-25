{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE NamedFieldPuns #-}
{-|
Module: Crypto.Spake2.Group
Description: Interface for mathematical groups
-}
module Crypto.Spake2.Group
  ( Group(..)
  , decodeScalar
  , elementSizeBytes
  , scalarSizeBytes
  , KeyPair(..)
  ) where

import Protolude hiding (group, length)

import Crypto.Error (CryptoFailable(..))
import Crypto.Random.Types (MonadRandom(..))
import Data.ByteArray (ByteArray, ByteArrayAccess(..))

import Crypto.Spake2.Util (bytesToNumber)

-- | A mathematical group intended to be used with SPAKE2.
--
-- Notes:
--  * This is a much richer interface than one would expect from a group purely derived from abstract algebra
--  * jml thinks this is relevant to all Diffie-Hellman cryptography,
--    but too ignorant to say for sure
--  * Is this group automatically abelian? cyclic?
--    Must it have these properties?
class Group group where
  -- | An element of the group.
  type Element group :: *

  -- | A scalar for this group.
  -- Mathematically equivalent to an integer,
  -- but possibly stored differently for computational reasons.
  type Scalar group :: *

  -- | Group addition.
  --
  -- prop> \x y z -> elementAdd group (elementAdd group x y) z == elementAdd group x (elementAdd group y z)
  elementAdd :: group -> Element group -> Element group -> Element group

  -- | Inverse with respect to group addition.
  --
  -- prop> \x -> (elementAdd group x (elementNegate group x)) == groupIdentity
  -- prop> \x -> (elementNegate group (elementNegate group x)) == x
  elementNegate :: group -> Element group -> Element group

  -- | Subtract one element from another.
  --
  -- prop> \x y -> (elementSubtract group x y) == (elementAdd group x (elementNegate group y))
  elementSubtract :: group -> Element group -> Element group -> Element group
  elementSubtract group x y = elementAdd group x (elementNegate group y)

  -- | Identity of the group.
  --
  -- Note [Added for completeness]
  --
  -- prop> \x -> (elementAdd group x groupIdentity) == x
  -- prop> \x -> (elementAdd group groupIdentity x) == x
  groupIdentity :: group -> Element group

  -- | Multiply an element of the group with respect to a scalar.
  --
  -- This is equivalent to adding the element to itself N times, where N is a scalar.
  scalarMultiply :: group -> Scalar group -> Element group -> Element group

  -- | Get the scalar that corresponds to an integer.
  --
  -- Note [Added for completeness]
  --
  -- prop> \x -> scalarToInteger group (integerToScalar group x) == x
  integerToScalar :: group -> Integer -> Scalar group

  -- | Get the integer that corresponds to a scalar.
  --
  -- Note [Added for completeness]
  --
  -- prop> \x -> integerToScalar group (scalarToInteger group x) == x
  scalarToInteger :: group -> Scalar group -> Integer

  -- | Encode an element of the group into bytes.
  --
  -- Note [Byte encoding in Group]
  --
  -- prop> \x -> decodeElement group (encodeElement group x) == CryptoPassed x
  encodeElement :: ByteArray bytes => group -> Element group -> bytes

  -- | Decode an element into the group from some bytes.
  --
  -- Note [Byte encoding in Group]
  decodeElement :: ByteArray bytes => group -> bytes -> CryptoFailable (Element group)

  -- | Encode a scalar into bytes.
  -- | Generate a new random element of the group, with corresponding scalar.
  generateElement :: MonadRandom randomly => group -> randomly (KeyPair group)

  -- | Size of elements, in bits
  elementSizeBits :: group -> Int

  -- | Size of scalars, in bits
  scalarSizeBits :: group -> Int

  -- | Deterministically create an arbitrary element from a seed bytestring.
  --
  -- __XXX__: jml would much rather this take a scalar, an element, or even an integer, rather than bytes
  -- because bytes mean that the group instances have to know about hash algorithms and HKDF.
  -- If the IntegerGroup class in SPAKE2 also oversized its input,
  -- then it and the ed25519 implementation would have identical decoding.
  arbitraryElement :: ByteArrayAccess bytes => group -> bytes -> Element group


-- | Map some arbitrary bytes into a scalar in a group.
decodeScalar :: (ByteArrayAccess bytes, Group group) => group -> bytes -> Scalar group
decodeScalar group bytes = integerToScalar group (bytesToNumber bytes)

-- | Size of elements in a group, in bits.
elementSizeBytes :: Group group => group -> Int
elementSizeBytes group = (elementSizeBits group + 7) `div` 8

-- | Size of scalars in a group, in bytes.
scalarSizeBytes :: Group group => group -> Int
scalarSizeBytes group = (scalarSizeBits group + 7) `div` 8

-- | A group key pair composed of the private part (a scalar)
-- and a public part (associated group element).
data KeyPair group
  = KeyPair
  { keyPairPublic :: !(Element group)
  , keyPairPrivate :: !(Scalar group)
  }

{-
Note [Byte encoding in Group]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

jml is unsure whether it is a good idea to put encode/decode methods in the 'Group' typeclass.

Reasons for:

 * cryptonite does it with 'EllipticCurve'
 * warner does it with spake2.groups

Reasons against:

 * mathematical structure of groups has no connection to serialization
 * might want multiple encodings for same mathematical group

Including for now on the assumption that I'm ignorant.

TODO: Revisit decision to put byte encoding in Group after we've done a couple of implementations
-}

{-
Note [Added for completeness]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Several methods were added to 'Group' out of a desire for mathematical completeness
rather than necessity for implementing SPAKE2.

These include:

 * 'groupIdentity' -- because groups have identities (just like semigroups)
 * 'scalarToInteger' and 'integerToScalar' -- because scalars are mathematically integers
 * 'encodeScalar' -- because having an inverse of 'decodeScalar' makes it easier to test

-}
