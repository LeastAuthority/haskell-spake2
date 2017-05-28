{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE TypeFamilies #-}
{-|
Module: Crypto.Spake2.Groups
Description: Additive group of integers modulo \(n\)

Do __NOT__ use this for anything cryptographic.
-}
module Crypto.Spake2.Groups.IntegerAddition
  ( IntegerAddition(..)
  ) where

import Protolude hiding (group, length)

import Crypto.Error (CryptoFailable(..))
import Crypto.Number.Basic (numBits)
import Crypto.Number.ModArithmetic (expSafe)
import Crypto.Random.Types (MonadRandom(..))

import Crypto.Spake2.Group
  ( Group(..)
  , KeyPair(..)
  , decodeScalar
  , elementSizeBytes
  , scalarSizeBytes
  )
import Crypto.Spake2.Util
  ( expandArbitraryElementSeed
  , bytesToNumber
  , unsafeNumberToBytes
  )

-- | Simple integer addition group.
--
-- Do __NOT__ use this for anything cryptographic.
newtype IntegerAddition = IntegerAddition { modulus :: Integer } deriving (Eq, Ord, Show)

instance Group IntegerAddition where
  type Element IntegerAddition = Integer
  type Scalar IntegerAddition = Integer

  elementAdd group x y = (x + y) `mod` modulus group
  elementNegate group x = negate x `mod` modulus group
  elementSubtract group x y = (x - y) `mod` modulus group
  groupIdentity _ = 0
  scalarMultiply group n x = (n * x) `mod` modulus group
  integerToScalar _ x = x
  scalarToInteger _ x = x
  encodeElement group x = unsafeNumberToBytes (elementSizeBytes group) (x `mod` modulus group)
  decodeElement _ bytes = CryptoPassed (bytesToNumber bytes)
  generateElement group = do
    scalarBytes <- getRandomBytes (scalarSizeBytes group)
    let scalar = decodeScalar group (scalarBytes :: ByteString)
    let element = scalarMultiply group scalar (groupIdentity group)
    pure (KeyPair element scalar)
  scalarSizeBits group = numBits (modulus group)  -- XXX: Incorrect value. Not sure what it should be.
  elementSizeBits group = numBits (modulus group) -- XXX: should be size of subgroup
  arbitraryElement group seed =
    let processedSeed = expandArbitraryElementSeed seed (elementSizeBytes group) :: ByteString
        r = (modulus group - 1) `div` modulus group -- XXX: should be size of subgroup
        h = bytesToNumber processedSeed `mod` modulus group
    in expSafe h r (modulus group)


