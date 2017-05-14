{-# LANGUAGE NamedFieldPuns #-}
module Crypto.Spake2.Groups
  ( Element
  , IntegerGroup
  , arbitraryElement
  , bytesToElement
  , expandArbitraryElementSeed
  ) where

import Protolude hiding (group, length)

import Crypto.Hash.Algorithms (SHA256)
import qualified Crypto.KDF.HKDF as HKDF
import Crypto.Number.Basic (numBytes)
import Crypto.Number.ModArithmetic (expSafe)
import Crypto.Number.Serialize (os2ip)
import Data.ByteArray (ByteArray, ByteArrayAccess(..))


-- TODO: I don't understand enough about ECC or IntegerGroup to decide whether
-- it's OK to just use ECC, which is much better implemented in cryptonite
-- (e.g.
-- https://hackage.haskell.org/package/cryptonite-0.23/docs/Crypto-ECC.html#t:EllipticCurve)

data Error bytes
  = WrongSize bytes Int
  | WrongGroup bytes IntegerGroup
  | NotInField bytes Integer
  deriving (Eq, Ord, Show)

-- | Definitely about integers, but jml is not entirely sure why it's called a
-- group, since there's no inversion function, and since it also has scalar
-- multiplier.
data IntegerGroup
  = IntegerGroup
  { order :: Integer
  , fieldSize :: Integer
  , _generator :: Integer
  } deriving (Eq, Ord, Show)

type Bytes = Int  -- XXX: I guess this should be some sort of unsigned

elementSizeBytes :: IntegerGroup -> Bytes
elementSizeBytes group = numBytes (fieldSize group)

-- | An element of a group. It's up to you to remember which group this
-- element came from.
newtype Element = Element Integer deriving (Eq, Ord, Show)


arbitraryElement :: ByteArrayAccess ikm => IntegerGroup -> ikm -> Element
arbitraryElement group@IntegerGroup{order, fieldSize} seed =
  let processedSeed = expandArbitraryElementSeed seed (elementSizeBytes group) :: ByteString
      r = (order - 1) `div` fieldSize
      h = os2ip processedSeed `mod` order
  in Element (expSafe h r order)


bytesToElement :: ByteArrayAccess bytes => IntegerGroup -> bytes -> Either (Error bytes) Element
bytesToElement group@IntegerGroup{order} bytes = do
  unless (length bytes == size) $ throwError (WrongSize bytes size)
  let i = os2ip bytes
  unless (0 < i && i < order) $ throwError (NotInField bytes order)
  let element = Element i
  unless (isMember group element) $ throwError (WrongGroup bytes group)
  pure element
  where
    size = elementSizeBytes group

isMember :: IntegerGroup -> Element -> Bool
isMember IntegerGroup{order, fieldSize} (Element i) = expSafe i fieldSize order == 1

expandArbitraryElementSeed :: (ByteArrayAccess ikm, ByteArray out) => ikm -> Int -> out
expandArbitraryElementSeed value size =
  HKDF.expand prk info size
  where
    prk :: HKDF.PRK SHA256
    prk = HKDF.extract salt value

    salt, info :: ByteString
    salt = ""
    info = "SPAKE 2 arbitrary element"
