{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NamedFieldPuns #-}

{-|
Module: Crypto.Spake2.Math
Description: The mathematical implementation of SPAKE2.

This module ignores everything about networks, bytes, encoding, hash
functions, and so forth. All it does is provide the mathematical building
blocks for SPAKE2, as per [Simple Password-Based Encrypted Key Exchange
Protocols](http://www.di.ens.fr/~pointche/Documents/Papers/2005_rsa.pdf) by
Michel Abdalla and David Pointcheval.

== How to use it

=== Both sides

Both sides need to have something like this.

@
import qualified Crypto.Spake2.Math as Math

curve :: Proxy Curve_P521R1
curve = Proxy

m, n :: Point Curve_P521R1
m = hardcodedPoint
n = otherHardcodedPoint

-- Example for creating a password point from a bytestring. You'll need to
-- have the password expressed as a scalar.
password :: Scalar Curve_521R1
password =
  case decodePoint curve "secretMagicWord" of
    CryptoPassed pw -> pw  -- TODO: This generates a Point, how do we find the corresponding scalar?
    CryptoFailed err -> panic ("Could not generate password: " <> show err)

createSessionKey :: sideID -> sideID -> Point Curve_P521R1 -> Point Curve_P521R1 -> Point Curve_P521R1 -> ByteString
createSessionKey = notImplemented -- You'll have to figure this out. Some sort of hash of the inputs.
@

=== Side A

@
runSpake2 = do
  let params = Math.Params curve m n
  let spake2 = Math.Spake2 params password
  spake2Exchange <- Math.startSpake2 spake2
  let outbound = Math.computeOutboundMessage spake2Exchange
  sendOutboundMessage outbound
  -- NOTE: We could wait for this before sending the outbound. Depends on the
  -- network protocol you're arranging with your application.
  inbound <- waitForInboundMessage
  let key = Math.generateKeyMaterial spake2Exchange
  createSessionKey sideA sideB outbound inbound key
@

=== Side B

The same as Side A, but @n@ and @m@ are swapped around.

@
runSpake2 = do
  let params = Math.Params curve n m
  let spake2 = Math.Spake2 params password
  inbound <- waitForInboundMessage
  spake2Exchange <- Math.startSpake2 spake2
  let outbound = Math.computeOutboundMessage spake2Exchange
  sendOutboundMessage outbound
  let key = Math.generateKeyMaterial spake2Exchange
  createSessionKey sideA sideB outbound inbound key
@

-}

module Crypto.Spake2.Math
  ( Spake2(..)  -- XXX: Not sure want to export innards but it disables "unused" warning
  , Params(..)  -- XXX: ditto
  , startSpake2
  , Spake2Exchange
  , computeOutboundMessage
  , generateKeyMaterial
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
data Spake2Exchange curve
  = Started
  { spake2 :: Spake2 curve -- ^ Description of the specific instance of the
                           -- SPAKE2 protocol we are using. Parameters,
                           -- password, and group must be the same for this to
                           -- work.
  , xy :: KeyPair curve -- ^ Arbitrary point chosen by this side of the
                        -- exchange. It is kept secret, and is only used to
                        -- negotiate an exchange. A "blinded" form is sent to
                        -- the other side of the protocol.
  }

-- | Initiate the SPAKE2 exchange. Generates a secret (@xy@) that will be held
-- by this side, and transmitted to the other side in "blinded" form.
startSpake2 :: (EllipticCurve curve, MonadRandom randomly) => Spake2 curve -> randomly (Spake2Exchange curve)
startSpake2 spake2' = Started spake2' <$> curveGenerateKeyPair (proxy . params $ spake2')

-- | Determine the point (either \(X^{\star}\) or \(Y^{\star}\)) to send to the other side.
computeOutboundMessage :: EllipticCurveArith curve => Spake2Exchange curve -> Point curve
computeOutboundMessage Started{spake2 = Spake2{params = Params{proxy, ourBlind}, password}, xy} =
  pointAdd proxy (keypairGetPublic xy) (pointSmul proxy password ourBlind)

-- | Generate key material, \(K\), given a message from the other side (either
-- \(Y^{\star}\) or \(X^{\star}\)).
--
-- This key material is the last piece of input required to make the session
-- key, \(SK\), which should be generated as:
--
--   \[SK \leftarrow H(A, B, X^{\star}, Y^{\star}, K)\]
--
-- Where:
--
-- * \(H\) is a hash function
-- * \(A\) identifies the initiating side
-- * \(B\) identifies the receiving side
-- * \(X^{star}\) is the outbound message from the initiating side
-- * \(Y^{star}\) is the outbound message from the receiving side
-- * \(K\) is the result of this function
--
-- __XXX__: jml can't figure out how to do group division within the
-- constraints of 'EllipticCurveArith', so we are also constraining the scalar
-- to be number that we can negate. This works because \(X/Y\) is \(X \cdot
-- Y^{-1}\) and, more generally, \(X/Y^{n}\) is \(X \cdot Y^{-n}\), where
-- \(\cdot\) is 'pointAdd' and exponentiation is 'pointSmul'.
generateKeyMaterial
  :: (Num (Scalar curve), EllipticCurveArith curve)
  => Spake2Exchange curve  -- ^ An initiated SPAKE2 exchange
  -> Point curve  -- ^ The outbound message from the other side (i.e. inbound to us)
  -> Point curve -- ^ The final piece of key material to generate the session key.
generateKeyMaterial Started{spake2 = Spake2{params = Params{proxy, theirBlind}, password}, xy} inbound =
  pointSmul proxy (keypairGetPrivate xy) (pointAdd proxy inbound (pointSmul proxy (negate password) theirBlind))
