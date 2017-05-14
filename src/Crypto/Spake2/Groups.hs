{-# LANGUAGE NamedFieldPuns #-}
module Crypto.Spake2.Groups
  ( IntegerGroup
  , arbitraryElement
  ) where

import Protolude hiding (group)

import Crypto.Hash.Algorithms (SHA256)
import qualified Crypto.KDF.HKDF as HKDF
import Crypto.Number.Basic (numBytes)
import Crypto.Number.ModArithmetic (expSafe)
import Crypto.Number.Serialize (os2ip)
import Data.ByteArray (ByteArray, ByteArrayAccess)


-- TODO: I don't understand enough about ECC or IntegerGroup to decide whether
-- it's OK to just use ECC, which is much better implemented in cryptonite
-- (e.g.
-- https://hackage.haskell.org/package/cryptonite-0.23/docs/Crypto-ECC.html#t:EllipticCurve)

data IntegerGroup
  = IntegerGroup
  { order :: Integer
  , fieldSize :: Integer
  , generator :: Integer
  } deriving (Eq, Ord, Show)

type Bytes = Int  -- XXX: I guess this should be some sort of unsigned

elementSizeBytes :: IntegerGroup -> Bytes
elementSizeBytes group = numBytes (fieldSize group)

data Element
  = Element
  { fromGroup :: IntegerGroup
  , element :: Integer
  } deriving (Eq, Ord, Show)


arbitraryElement :: ByteArrayAccess ikm => IntegerGroup -> ikm -> Element
arbitraryElement group@IntegerGroup{order, fieldSize} seed =
  let processedSeed = expandArbitraryElementSeed seed (elementSizeBytes group) :: ByteString
      r = (order - 1) `div` fieldSize
      h = os2ip processedSeed `mod` order
  in Element group (expSafe h r order)

expandArbitraryElementSeed :: (ByteArrayAccess ikm, ByteArray out) => ikm -> Int -> out
expandArbitraryElementSeed value size =
  HKDF.expand prk info size
  where
    prk :: HKDF.PRK SHA256
    prk = HKDF.extract salt value

    salt, info :: ByteString
    salt = ""
    info = "SPAKE 2 arbitrary element"
