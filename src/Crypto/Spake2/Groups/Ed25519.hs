{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE TypeFamilies #-}
{-|
Module: Crypto.Spake2.Groups.Ed25519
Description: Ed25519 group for SPAKE2

Derived from @ed25519_basic.py@ in [python-spake2](https://github.com/warner/python-spake2),
in turn derived from the slow, reference, Python implementation at
<http://ed25519.cr.yp.to/python/ed25519.py>
-}
module Crypto.Spake2.Groups.Ed25519
  ( Ed25519(..)
  -- * Exported for testing
  , l
  , generator
  ) where

import Protolude hiding (clamp, group, zero)

import Crypto.Error (CryptoFailable(..), CryptoError(..))
import Crypto.Number.Generate (generateMax)
import Crypto.Number.ModArithmetic (expSafe, inverseCoprimes)
import Crypto.Number.Serialize (i2osp, os2ip)
import Data.ByteArray (ByteArray, ByteArrayAccess)
import qualified Data.ByteArray as ByteArray
import qualified Data.List as List

import Crypto.Spake2.Group (AbelianGroup(..), Group(..), KeyPair(..), scalarSizeBytes)
import Crypto.Spake2.Util (bytesToNumber, expandArbitraryElementSeed)

{-
Note [Ed25519 vs curve25519]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As best as jml can tell,

* X25519 is Elliptic Curve Diffie-Hellman (ECDH) over Curve25519
* Ed25519 is Edwards-curve Digital Signature Algorithm (EdDSA) over Curve25519

(quoted from a [StackOverflow answer](https://crypto.stackexchange.com/questions/27866/why-curve25519-for-encryption-but-ed25519-for-signatures))

This means the underlying curve is the same,
and Ed25519 is the use of that curve in signing,
and X25519 is the curve used in key exchange.

Complicated by the fact that Curve25519 /used/ to be the name of ECDH over Curve25519.

Since our primary goal is Python interoperability,
we are going to implement an analogue of the Python code here,
and call it Ed25519.

Once that is done, we can explore using Cryptonite's Curve25519 logic,
ideally demonstrating its equivalence with some automated tests.

<https://security.stackexchange.com/questions/50878/ecdsa-vs-ecdh-vs-ed25519-vs-curve25519>
<https://crypto.stackexchange.com/questions/27866/why-curve25519-for-encryption-but-ed25519-for-signatures>
-}

data Ed25519 = Ed25519 deriving (Eq, Show)

instance Group Ed25519 where
  type Element Ed25519 = ExtendedPoint 'Member

  elementAdd _ x y = addExtendedPoints x y
  elementNegate group = scalarMultiply group (l - 1)
  groupIdentity _ = assertInGroup extendedZero

  encodeElement _ x = encodeAffinePoint (extendedToAffine' x)
  decodeElement _ bytes = toCryptoFailable $ do
    extended <- affineToExtended <$> decodeAffinePoint bytes
    ensureInGroup extended

  elementSizeBits _ = 255

  arbitraryElement group bytes =
    let seed = expandArbitraryElementSeed bytes (scalarSizeBytes group + 16) :: ByteString
        y = bytesToNumber seed `mod` q
    in
    List.head [ element | Right element <- map makeGroupMember [y..] ]

instance AbelianGroup Ed25519 where
  type Scalar Ed25519 = Integer

  scalarMultiply _ n x = safeScalarMultiply n x

  integerToScalar _ x = x
  scalarToInteger _ x = x

  scalarSizeBits _ = 255

  generateElement group = do
    scalar <- generateMax l
    let element = scalarMultiply group scalar generator
    pure (KeyPair element scalar)


-- | Errors that can occur within the group.
data Error
  = NotOnCurve Integer Integer
  | NotInGroup (ExtendedPoint 'Unknown)
  | LowOrderPoint (ExtendedPoint 'Unknown)
  deriving (Eq, Show)

-- | Translate internal errors into CryptoFailable.
toCryptoFailable :: Either Error a -> CryptoFailable a
toCryptoFailable (Right r) = pure r
toCryptoFailable (Left _) = CryptoFailed CryptoError_PointCoordinatesInvalid

-- | Guarantee an element is in the Ed25519 subgroup.
ensureInGroup :: ExtendedPoint 'Unknown -> Either Error (ExtendedPoint 'Member)
ensureInGroup element@ExtendedPoint{x, y, z, t} =
  if isExtendedZero (safeScalarMultiply l element)
  then pure ExtendedPoint { x = x, y = y, z = z, t = t}
  else  throwError $ NotInGroup element

-- | Assert that an element is the Ed25519 subgroup.
--
-- Panics if it is not.
assertInGroup :: HasCallStack => ExtendedPoint 'Unknown -> ExtendedPoint 'Member
assertInGroup element =
  -- XXX: Should we force evaluation of this? We mostly use it only for
  -- constants.
  case ensureInGroup element of
    Left err -> panic $ "Element not in group (" <> show err <> "): " <> show element
    Right x -> x

-- TODO: Document this.
-- Guess: the size of the subgroup? the group?
q :: Integer
q = 2 ^ 255 - 19  -- XXX: force eval?

-- | The order of the group represented by 'Ed25519'.
--
-- Note that this is a subgroup of the underlying elliptic curve.
l :: Integer
l = 2 ^ 252 + 27742317777372353535851937790883648493

-- TODO document this
dConst :: Integer
dConst = -121665 * inv 121666  -- XXX: force eval?

-- TODO document this
i :: Integer
i = expSafe 2 ((q-1) `div` 4) q  -- XXX: force eval

-- | The generator for the (sub)group represented by 'Ed25519'.
generator :: Element Ed25519
generator = assertInGroup $ affineToExtended b
  where
    b = case makeAffinePoint (x `mod` q) (y `mod` q) of
          Left err -> panic $ "Generator is not affine point: " <> show err
          Right r -> r
    x = xRecover y
    y = 4 * inv 5

-- | Calculate the inverse of @x@ modulo 'q'.
--
-- Assumes that @x@ is coprime with 'q' and non-zero.
-- Will raise an exception if either of these assumptions is false.
--
-- prop> \x -> (x * inv x) `mod` q == 1
inv :: Integer -> Integer
inv x = inverseCoprimes x q

xRecover :: Integer -> Integer
xRecover y =
  let x'' = (y * y - 1) * inv(dConst * y * y + 1)
      x' = expSafe x'' ((q + 3) `div` 8) q
      x = if (x' * x' - x'') `mod` q /= 0
          then (x' * i) `mod` q
          else x'
  in
    if even x then x else q - x


-- | Whether or not an extended point is a member of Ed25519.
data GroupMembership = Unknown | Member

-- | A point that might be a member of Ed25519.
-- Note: [Extended coordinates]
data ExtendedPoint (groupMembership :: GroupMembership)
  = ExtendedPoint
  { x :: !Integer
  , y :: !Integer
  , z :: !Integer
  , t :: !Integer
  } deriving (Show)

-- XXX: jml unsure about overriding equality like this.
-- Note: [Extended coordinates]
instance Eq (ExtendedPoint a) where
  point1 == point2 = extendedToAffine' point1 == extendedToAffine' point2

-- | Zero in the extended coordinate space.
--
-- > affineZero = AffinePoint{x = 0, y = 1}
-- > extendedZero == affineToExtended affineZero
--
-- Note: [Extended coordinates]
extendedZero :: ExtendedPoint a
extendedZero = ExtendedPoint {x = 0, y = 1, z = 1, t = 0}

-- | Check if a point is equivalent to zero.
--
-- jml is unsure, but this probably exists because it might be faster than
-- mapping to affine space and checking for equality.
--
-- Note: [Extended coordinates]
isExtendedZero :: ExtendedPoint irrelevant -> Bool
isExtendedZero ExtendedPoint{x, y, z} = x == 0 && y' == z' && y' /= 0
  where
    y' = y `mod` q
    z' = z `mod` q

-- | Add two extended points.
--
-- The points don't have to be in the Ed25519 subgroup, and we can't say
-- anything about whether the result will be.
--
-- add-2008-hwcd-3
addExtendedPoints :: ExtendedPoint a -> ExtendedPoint a -> ExtendedPoint a
addExtendedPoints ExtendedPoint{x = x1, y = y1, z = z1, t = t1} ExtendedPoint{x = x2, y = y2, z = z2, t = t2} =
  ExtendedPoint{x = x3, y = y3, z = z3, t = t3}
  where
    -- X3 = (E*F) % Q
    x3 = (e * f) `mod` q
    -- Y3 = (G*H) % Q
    y3 = (g * h) `mod` q
    -- Z3 = (F*G) % Q
    z3 = (f * g) `mod` q
    -- T3 = (E*H) % Q
    t3 = (e * h) `mod` q

    -- E = (B-A) % Q
    e = (b - a) `mod` q
    -- F = (D-C) % Q
    f = (d' - c) `mod` q
    -- G = (D+C) % Q
    g = (d' + c) `mod` q
    -- H = (B+A) % Q
    h = (b + a) `mod` q

    -- A = ((Y1-X1)*(Y2-X2)) % Q
    a = ((y1 - x1) * (y2 - x2)) `mod` q
    -- B = ((Y1+X1)*(Y2+X2)) % Q
    b = ((y1 + x1) * (y2 + x2)) `mod` q
    -- C = T1*(2*d)*T2 % Q
    c = (t1 * (2 * dConst) * t2) `mod` q
    -- D = Z1*2*Z2 % Q
    d' = (z1 * 2 * z2) `mod` q

-- | Double an extended point.
--
-- dbl-2008-hwcd
doubleExtendedPoint :: ExtendedPoint preserving -> ExtendedPoint preserving
doubleExtendedPoint ExtendedPoint{x = x1, y = y1, z = z1} =
  ExtendedPoint{x= x3, y = y3, z = z3, t = t3}
  where
    -- X3 = (E*F) % Q
    x3 = (e * f) `mod` q
    -- Y3 = (G*H) % Q
    y3 = (g * h) `mod` q
    -- Z3 = (F*G) % Q
    z3 = (f * g) `mod` q
    -- T3 = (E*H) % Q
    t3 = (e * h) `mod` q

    -- E = (J*J-A-B) % Q
    e = (j * j - a -b) `mod` q
    -- F = (G-C) % Q
    f = (g - c) `mod` q
    -- G = (D+B) % Q
    g = (d' + b) `mod` q
    -- H = (D-B) % Q
    h = (d' - b) `mod` q

    -- A = (X1*X1)
    a = x1 * x1
    -- B = (Y1*Y1)
    b = y1 * y1
    -- C = (2*Z1*Z1)
    c = 2 * z1 * z1
    -- D = (-A) % Q
    d' = (-a) `mod` q
    -- J = (X1+Y1) % Q
    j = (x1 + y1) `mod` q

-- | Multiply a point (might be in the group, might not) by a scalar.
safeScalarMultiply :: Integer -> ExtendedPoint a -> ExtendedPoint a
safeScalarMultiply n = scalarMultiplyExtendedPoint addExtendedPoints n

-- | Scalar multiplication parametrised by addition.
scalarMultiplyExtendedPoint :: (ExtendedPoint a -> ExtendedPoint a -> ExtendedPoint a) -> Integer -> ExtendedPoint a -> ExtendedPoint a
scalarMultiplyExtendedPoint _ 0 _    = extendedZero
scalarMultiplyExtendedPoint add n x
  | n >= l    = scalarMultiplyExtendedPoint add (n `mod` l) x
  | even n    = doubleExtendedPoint (scalarMultiplyExtendedPoint add (n `div` 2) x)
  | n == 1    = x
  | n <= 0    = panic $ "Unexpected negative multiplier: " <> show n
  | otherwise = add x (scalarMultiplyExtendedPoint add (n - 1) x)


-- | Attempt to create a member of Ed25519 from an affine @y@ coordinate.
makeGroupMember :: Integer -> Either Error (Element Ed25519)
makeGroupMember y = do
  point <- affineToExtended <$> makeAffinePoint (xRecover y) y
  let point8 = safeScalarMultiply 8 point
  if isExtendedZero point8
    then throwError $ LowOrderPoint point
    else ensureInGroup point8

{-
Note: [Arbitrary point generation]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is cribbed from warner's notes in python-spake2:
<https://github.com/warner/python-spake2/blob/05b9f968d37dc5419f0e6e20c9b65737de21a7e9/src/spake2/ed25519_basic.py#L291>

* only about 50% of Y coordinates map to valid curve points
* even if the point is on our curve, it may not be in our particular (order=l) subgroup
  The curve has order 8*L, so an arbitrary point could have order 1,2,4,8,1*L,2*L,4*L,8*L
  (everything which divides the group order)
* 50% of random points will have order 8*L,
  25% will have order 4*L,
  13% order 2*L,
  13% will have our desired order 1*L
  (and a vanishingly small fraction will have 1/2/4/8).
* If we multiply any of the 8*L points by 2, we're sure to get an 4*L point
  (and multiplying a 4*L point by 2 gives us a 2*L point, and so on).
* Multiplying a 1*L point by 2 gives us a different 1*L point.
  So multiplying by 8 gets us from almost any point into a uniform point on the correct 1*L subgroup.
* We might still get really unlucky and pick one of the 8 low-order points.
  Multiplying by 8 will get us to the identity (Zero), which we check for explicitly.
* Double check that *this* point (8 * P) is in the right subgroup.

That final check is a Python assertion,
which would crash the program if incorrect.
For programming convenience, I just skip these values.

jml doesn't know what is meant by the 'order' of a point.

-}

-- TODO: Document this
data AffinePoint
  = AffinePoint
  { x :: !Integer
  , y :: !Integer
  } deriving (Eq, Show)

-- | Construct an affine point that is on Curve25519.
makeAffinePoint :: Integer -> Integer -> Either Error AffinePoint
makeAffinePoint x y
  | isOnCurve x y = pure AffinePoint { x = x, y = y }
  | otherwise = throwError $ NotOnCurve x y
  where
    isOnCurve x' y' = ((-x') * x' + y' * y' - 1 - dConst * x' * x' * y' * y') `mod` q == 0

-- | Encode an 'AffinePoint' into bytes.
--
-- MSB of the output is whether or not @x@ is even (i.e. @x .&. 1@),
-- teh rest of the output is little-endian @y@.
encodeAffinePoint :: (ByteArray bytes, ByteArrayAccess bytes) => AffinePoint -> bytes
encodeAffinePoint AffinePoint{x, y}
  | even x = numberToLitteEndianBytes y
  | otherwise = numberToLitteEndianBytes (y + shift 1 255)

decodeAffinePoint :: (ByteArray bytes, ByteArrayAccess bytes) => bytes -> Either Error AffinePoint
decodeAffinePoint bytes =
  let unclamped = littleEndianBytesToNumber bytes
      clamp = shift 1 255 - 1
      y = unclamped .&. clamp
      x = xRecover y
      x' = if x .&. 1 == unclamped .&. shift 1 255 then x else q - x
  in makeAffinePoint x' y


numberToLitteEndianBytes :: ByteArray bytes => Integer -> bytes
numberToLitteEndianBytes n = ByteArray.pack (reverse (ByteArray.unpack (i2osp n :: ByteString)))

littleEndianBytesToNumber :: (ByteArray bytes, ByteArrayAccess bytes) => bytes -> Integer
littleEndianBytesToNumber bytes = os2ip (ByteArray.pack (reverse (ByteArray.unpack bytes)) :: ByteString)

{-
Note: [Extended coordinates]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

jml only partly understands these. Here's that understanding.

The underlying elliptic curve is two-dimensional.
These are the AffinePoints.
We project that curve into a 4-dimensional space,
i.e. to the ExtendedPoints.

Doing so makes some of the arithmetic faster.
But ultimately, the values we are interested in are the affine points.

Thus, even if two ExtendedPoints have differing values internally,
they might be equivalent with respect to the Ed25519 group.

That is,
the affine points form a group
the extended points form a group
you can get a subgroup of the extended points group isomorphic to the affine points group
by using "maps to the same affine point" as an equivalence relation.

The Python version goes to some lengths to avoid doing calculations with zero.
In an earlier revision, I preserved that behaviour,
however, I have since removed it,
as we have no performance data,
and it adds extra complexity.

This URL might help:
http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
-}

affineToExtended :: AffinePoint -> ExtendedPoint 'Unknown
affineToExtended AffinePoint{x, y} =
  ExtendedPoint
  { x = x `mod` q
  , y = y `mod` q
  , z = 1
  , t = (x * y) `mod` q
  }

extendedToAffine' :: ExtendedPoint a -> AffinePoint
extendedToAffine' ExtendedPoint{x, y, z} =
  case makeAffinePoint x' y' of
    Left err -> panic $ "Could not make affine point: " <> show err
    Right r -> r
  where
    x' = (x * inv z) `mod` q
    y' = (y * inv z) `mod` q
