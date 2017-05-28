{-|
Module: Crypto.Spake2.Util
Description: Miscellany. Mostly to do with serialization.
-}
module Crypto.Spake2.Util
  ( expandData
  , expandArbitraryElementSeed
  , bytesToNumber
  , numberToBytes
  , unsafeNumberToBytes
  ) where

import Protolude

import Crypto.Hash.Algorithms (SHA256)
import Crypto.Number.Serialize (os2ip, i2ospOf, i2ospOf_)
import qualified Crypto.KDF.HKDF as HKDF
import Data.ByteArray (ByteArray, ByteArrayAccess(..))

-- TODO: memory package (a dependency of cryptonite) has
-- Data.ByteArray.Encoding, which does base16 encoding. Perhaps we should use
-- that rather than third-party base16-bytestring library.

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
expandArbitraryElementSeed =
  -- NOTE: This must be exactly this string in order to interoperate with python-spake2
  expandData "SPAKE2 arbitrary element"


-- | Serialize a number according to the SPAKE2 protocol.
--
-- Just kidding, there isn't a SPAKE2 protocol.
-- This just matches the Python implementation.
--
-- Inverse of 'bytesToNumber'.
numberToBytes :: ByteArray bytes => Int -> Integer -> Maybe bytes
numberToBytes = i2ospOf

-- | Serialize a number according to the SPAKE2 protocol.
--
-- Panics if the number is too big to fit into the given number of bytes.
unsafeNumberToBytes :: ByteArray bytes => Int -> Integer -> bytes
unsafeNumberToBytes = i2ospOf_


-- | Deserialize a number according to the SPAKE2 protocol.
--
-- Just kidding, there isn't a SPAKE2 protocol.
-- This just matches the Python implementation.
--
-- Inverse of 'numberToBytes'.
bytesToNumber :: ByteArrayAccess bytes => bytes -> Integer
bytesToNumber = os2ip
