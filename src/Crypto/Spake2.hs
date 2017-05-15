{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
module Crypto.Spake2
  ( something
  , Spake2(..)  -- XXX: Not sure want to export innards but it disables "unused" warning
  , makeSpake2
  , startSpake2
  , Started(..) -- XXX: ditto
  , Params(..)  -- XXX: ditto
  , makeParams
  , expandPassword
  ) where

import Protolude

import Crypto.ECC (EllipticCurve(..), KeyPair(..))
import Crypto.Random.Types (MonadRandom(..))
import Data.ByteArray (ByteArray, ByteArrayAccess)

import Crypto.Spake2.Groups (expandData)

something :: a -> a
something x = x

data Params curve
  = Params
  { proxy :: Proxy curve
  , m :: Point curve
  , n :: Point curve
  , s :: Point curve -- ^ Used for both sides of symmetric session.
  }

-- | Create parameters for SPAKE2.
makeParams :: (MonadRandom randomly, EllipticCurve curve) => Proxy curve -> randomly (Params curve)
makeParams proxy = Params proxy <$> generateElem <*> generateElem <*> generateElem
  where
    generateElem = keypairGetPublic <$> curveGenerateKeyPair proxy


newtype Password = Password ByteString

expandPassword :: (ByteArrayAccess bytes, ByteArray output) => Password -> Int -> output
expandPassword (Password bytes) numBytes = expandData "SPAKE2 password" bytes numBytes

data Spake2 curve
  = Spake2
  { params :: Params curve
  , password :: Password
  }

makeSpake2 :: Password -> Params curve -> Spake2 curve
makeSpake2 password params = Spake2 params password

data Started curve
  = Started
  { spake2 :: Spake2 curve
    -- XXX: I think this is the same as picking an arbitrary scalar and then
    -- projecting it into the 'element' space by multiplying it by the
    -- generating element
  , xy :: KeyPair curve
  }

startSpake2 :: (EllipticCurve curve, MonadRandom randomly) => Spake2 curve -> randomly (Started curve)
startSpake2 spake2' = Started spake2' <$> curveGenerateKeyPair (proxy . params $ spake2')

--computeOutboundMessage :: EllipticCurveArith curve => Started curve -> Point curve -> outbound
--computeOutboundMessage Started{xy} blinding =
--  notImplemented

