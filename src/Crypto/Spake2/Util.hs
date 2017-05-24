module Crypto.Spake2.Util
  ( expandData
  , expandArbitraryElementSeed
  ) where

import Protolude

import Crypto.Hash.Algorithms (SHA256)
import qualified Crypto.KDF.HKDF as HKDF
import Data.ByteArray (ByteArray, ByteArrayAccess(..))


-- | Take an arbitrary sequence of bytes and expand it to be the given number
-- of bytes. Do this by extracting a pseudo-random key and expanding it using
-- HKDF.
expandData :: (ByteArrayAccess input, ByteArray output) => ByteString -> input -> Int -> output
expandData info input size =
  HKDF.expand prk info size
  where
    prk :: HKDF.PRK SHA256
    prk = HKDF.extract salt input

    -- XXX: I'm no crypto expert, but hard-coding an empty string as a salt
    -- seems kind of weird.
    salt :: ByteString
    salt = ""

-- | Given a seed value for an arbitrary element (see 'arbitraryElement'),
-- expand it to be of the given length.
expandArbitraryElementSeed :: (ByteArrayAccess ikm, ByteArray out) => ikm -> Int -> out
expandArbitraryElementSeed = expandData "SPAKE 2 arbitrary element"
