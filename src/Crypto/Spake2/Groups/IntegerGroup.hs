{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE TypeFamilies #-}
{-|
Module: Crypto.Spake2.Groups.IntegerGroup
Description: Multiplicative group of integers modulo \(n\)
-}
module Crypto.Spake2.Groups.IntegerGroup
  ( IntegerGroup(..)
  , makeIntegerGroup
  , i1024
  ) where

import Protolude hiding (group, length)

import Crypto.Error (CryptoFailable(..), CryptoError(..))
import Crypto.Number.Basic (numBits)
import Crypto.Number.Generate (generateMax)
import Crypto.Number.ModArithmetic (expSafe)

import Crypto.Spake2.Group
  ( Group(..)
  , KeyPair(..)
  , elementSizeBytes
  )
import Crypto.Spake2.Util
  ( expandArbitraryElementSeed
  , bytesToNumber
  , unsafeNumberToBytes
  )

-- | A finite group of integers with respect to multiplication modulo the group order.
--
-- Construct with 'makeIntegerGroup'.
data IntegerGroup
  = IntegerGroup
  { order :: !Integer
  , subgroupOrder :: !Integer
  , generator :: !Integer
  } deriving (Eq, Show)

-- | Construct an 'IntegerGroup'.
--
-- Will fail if generator is '1',
-- since having the identity for a generator means the subgroup is the entire group.
--
-- TODO: Find other things to check for validity.
makeIntegerGroup :: Integer -> Integer -> Integer -> Maybe IntegerGroup
makeIntegerGroup _ _ 1 = Nothing
makeIntegerGroup order subgroupOrder generator = Just (IntegerGroup order subgroupOrder generator)


instance Group IntegerGroup where
  type Element IntegerGroup = Integer
  type Scalar IntegerGroup = Integer

  elementAdd group x y = (x * y) `mod` order group
  -- At a guess, negation is scalar multiplication where the scalar is -1
  elementNegate group x = expSafe x (subgroupOrder group - 1) (order group)
  groupIdentity _ = 1
  scalarMultiply group n x = expSafe x (n `mod` subgroupOrder group) (order group)
  integerToScalar group x = x `mod` subgroupOrder group  -- XXX: Should we instead fail?
  scalarToInteger _ n = n
  encodeElement group = unsafeNumberToBytes (elementSizeBytes group)
  decodeElement group bytes =
    case bytesToNumber bytes of
      x
        | x <= 0 || x >= order group -> CryptoFailed CryptoError_PointSizeInvalid
        | expSafe x (subgroupOrder group) (order group) /= groupIdentity group -> CryptoFailed CryptoError_PointCoordinatesInvalid
        | otherwise -> CryptoPassed x
  generateElement group = do
    scalar <- generateMax (subgroupOrder group)
    let element = scalarMultiply group scalar (generator group)
    pure (KeyPair element scalar)
  scalarSizeBits group = numBits (subgroupOrder group)
  elementSizeBits group = numBits (order group)
  arbitraryElement group seed =
    let processedSeed = expandArbitraryElementSeed seed (elementSizeBytes group) :: ByteString
        p = order group
        q = subgroupOrder group
        r = (p - 1) `div` q
        h = bytesToNumber processedSeed `mod` p
    in expSafe h r p

-- | 1024 bit integer group.
--
-- Originally from http://haofeng66.googlepages.com/JPAKEDemo.java,
-- via [python-spake2](https://github.com/warner/python-spake2).
i1024 :: IntegerGroup
i1024 =
  IntegerGroup
  { order = 0xE0A67598CD1B763BC98C8ABB333E5DDA0CD3AA0E5E1FB5BA8A7B4EABC10BA338FAE06DD4B90FDA70D7CF0CB0C638BE3341BEC0AF8A7330A3307DED2299A0EE606DF035177A239C34A912C202AA5F83B9C4A7CF0235B5316BFC6EFB9A248411258B30B839AF172440F32563056CB67A861158DDD90E6A894C72A5BBEF9E286C6B
  , subgroupOrder = 0xE950511EAB424B9A19A2AEB4E159B7844C589C4F
  , generator = 0xD29D5121B0423C2769AB21843E5A3240FF19CACC792264E3BB6BE4F78EDD1B15C4DFF7F1D905431F0AB16790E1F773B5CE01C804E509066A9919F5195F4ABC58189FD9FF987389CB5BEDF21B4DAB4F8B76A055FFE2770988FE2EC2DE11AD92219F0B351869AC24DA3D7BA87011A701CE8EE7BFE49486ED4527B7186CA4610A75
  }
