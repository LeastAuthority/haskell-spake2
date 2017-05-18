{-# LANGUAGE NamedFieldPuns #-}

{-|
Module: Crypto.Spake2.Math
Description: The mathematical implementation of SPAKE2.
-}

module Crypto.Spake2.Math
  ( Spake2(..)  -- XXX: Not sure want to export innards but it disables "unused" warning
  , startSpake2
  , Spake2Started(..)
  , computeOutboundMessage
  , Params(..)  -- XXX: ditto
  ) where

import Protolude

import Crypto.ECC (EllipticCurve(..), EllipticCurveArith(..), KeyPair(..))
import Crypto.Random.Types (MonadRandom(..))

-- | The parameters of the SPAKE2 protocol. The other side needs to be using
-- the same values, but with swapped values for 'ourBlind' and 'theirBlind'.
data Params curve
  = Params
  { proxy :: Proxy curve -- ^ The cyclic group used for encrypting keys
  , ourBlind :: Point curve -- ^ The "blind" we use when sending out values. Side A refers to this as \(M\) in the protocol description.
  , theirBlind :: Point curve -- ^ The "blind" the other side uses when sending values. Side A refers to this as \(N\) in the protocol description.
  }

-- | An instance of the SPAKE2 protocol. This represents one side of the protocol.
data Spake2 curve
  = Spake2
  { params :: Params curve
  , password :: Scalar curve
  }

-- | A SPAKE2 exchange that has been initiated.
data Spake2Started curve
  = Started
  { spake2 :: Spake2 curve
  , xy :: KeyPair curve
  }

-- | Initiate the SPAKE2 exchange. Generates a secret (@xy@) that will be held
-- by this side, and transmitted to the other side in "blinded" form.
startSpake2 :: (EllipticCurve curve, MonadRandom randomly) => Spake2 curve -> randomly (Spake2Started curve)
startSpake2 spake2' = Started spake2' <$> curveGenerateKeyPair (proxy . params $ spake2')

-- | Determine the point (either \(X^{\star}\) or \(Y^{\star}\)) to send to the other side.
computeOutboundMessage :: EllipticCurveArith curve => Spake2Started curve -> Point curve
computeOutboundMessage Started{spake2 = Spake2{params = Params{proxy, ourBlind}, password}, xy} =
  pointAdd proxy (keypairGetPublic xy) (pointSmul proxy password ourBlind)
