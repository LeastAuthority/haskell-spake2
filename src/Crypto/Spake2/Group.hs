{-# LANGUAGE TypeFamilies #-}
{-|
Module: Crypto.Spake2.Group
Description: Interfaces for mathematical groups
-}
module Crypto.Spake2.Group
  ( AbelianGroup(..)
  , Group(..)
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
class Group group where
  -- | An element of the group.
  type Element group :: *

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

  -- | Size of elements, in bits
  elementSizeBits :: group -> Int

  -- | Deterministically create an arbitrary element from a seed bytestring.
  --
  -- __XXX__: jml would much rather this take a scalar, an element, or even an integer, rather than bytes
  -- because bytes mean that the group instances have to know about hash algorithms and HKDF.
  -- If the IntegerGroup class in SPAKE2 also oversized its input,
  -- then it and the ed25519 implementation would have identical decoding.
  arbitraryElement :: ByteArrayAccess bytes => group -> bytes -> Element group


-- | A group where 'elementAdd' is commutative.
--
-- That is, where
--
-- prop> \x y -> elementAdd group x y == elementAdd group y x
--
-- This property leads to a natural \(\mathbb{Z}\)-module,
-- where scalar multiplication is defined as repeatedly calling `elementAdd`.
--
-- === Definitions
--
-- Warning: this gets algebraic.
--
-- A /module/ is a ring \(R\) together with an abelian group \((G, +)\),
-- and a new operator \(\cdot\) (i.e. scalar multiplication)
-- such that:
--
-- 1. \(r \cdot (x + y) = r \cdot x + r \cdot y\)
-- 2. \((r + s) \cdot x = r \cdot x + s \cdot x\)
-- 3. \((rs) \cdot x = r \cdot (s \cdot x)\)
-- 4. \(1_R \cdot x = x\)
--
-- for all \(x, y\) in \(G\), and \(r, s\) in \(R\),
-- where \(1_R\) is the identity of the ring.
--
-- A /ring/ \(R, +, \cdot\) a set \(R\) with two operators such that:
--
-- 1. \(R\) is an abelian group under \(+\)
-- 2. \(R\) is a monoid under \(\cdot\)
-- 3. \(cdot\) is _distributive_ with respect to \(+\). That is,
--    1. \(a \cdot (b + c) = (a \cdot b) + (a \cdot c) (left distributivity)
--    2. \((b + c) \cdot a) = (b \cdot a) + (c \cdot a) (right distributivity)
--
-- Note we have to define left & right distributivity,
-- because \(\cdot\) might not be commutative.
--
-- A /monoid/ is a group without the notion of inverse. See Haskell's 'Monoid' typeclass.
--
-- A \(\mathbb{Z}\)-module is a module where the ring \(R\)
-- is the integers with normal addition and multiplication.
class Group group => AbelianGroup group where
  -- | A scalar for this group.
  -- Mathematically equivalent to an integer,
  -- but possibly stored differently for computational reasons.
  type Scalar group :: *

  -- | Multiply an element of the group with respect to a scalar.
  --
  -- This is equivalent to adding the element to itself N times, where N is a scalar.
  -- The default implementation does exactly that.
  scalarMultiply :: group -> Scalar group -> Element group -> Element group
  scalarMultiply group scalar element =
    scalarMultiply' (scalarToInteger group scalar) element
    where
      scalarMultiply' 0 _ = groupIdentity group
      scalarMultiply' n x = elementAdd group x (scalarMultiply' (n - 1) x)

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

  -- | Size of scalars, in bits
  scalarSizeBits :: group -> Int

  -- | Encode a scalar into bytes.
  -- | Generate a new random element of the group, with corresponding scalar.
  generateElement :: MonadRandom randomly => group -> randomly (KeyPair group)


-- | Map some arbitrary bytes into a scalar in a group.
decodeScalar :: (ByteArrayAccess bytes, AbelianGroup group) => group -> bytes -> Scalar group
decodeScalar group bytes = integerToScalar group (bytesToNumber bytes)

-- | Size of elements in a group, in bits.
elementSizeBytes :: Group group => group -> Int
elementSizeBytes group = (elementSizeBits group + 7) `div` 8

-- | Size of scalars in a group, in bytes.
scalarSizeBytes :: AbelianGroup group => group -> Int
scalarSizeBytes group = (scalarSizeBits group + 7) `div` 8

-- | A group key pair composed of the private part (a scalar)
-- and a public part (associated group element).
data KeyPair group
  = KeyPair
  { keyPairPublic :: !(Element group)
  , keyPairPrivate :: !(Scalar group)
  }

{-
Note [Algebra]
~~~~~~~~~~~~~~

* Perhaps we should call 'AbelianGroup' 'ZModule' or similar?
* A "proper" implementation would no doubt have a Ring typeclass
  and then a new Module typeclass that somehow composed a Ring and an AbelianGroup.
  This seems unnecessary for our implementation needs,
  and is perhaps best left to those who know something about designing algebraic libraries.
* Cyclic groups are necessarily abelian.

-}

{-
Note [Byte encoding in Group]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

jml is unsure whether it is a good idea to put encode/decode methods in the 'Group' typeclass.

Reasons for:

 * cryptonite does it with 'EllipticCurve'
 * warner does it with spake2.groups
 * you just need to send different stuff over the wire for elliptic curve groups
   than integer modulo groups

Reasons against:

 * mathematical structure of groups has no connection to serialization
 * might want multiple encodings for same mathematical group
   (this seems unlikely)

We're keeping encode/decode in for now.
Later, we might want to split it out into a different typeclass,
perhaps one that inherits from the base 'Group' class.

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
