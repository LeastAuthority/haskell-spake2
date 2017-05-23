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

group :: Proxy Curve_P521R1
group = Proxy

m, n :: Element Curve_P521R1
m = hardcodedElement
n = otherHardcodedElement

-- Example for creating a password from a bytestring. You'll need to
-- have the password expressed as a scalar.
password :: Scalar Curve_521R1
password =
  case decodeElement group "secretMagicWord" of
    CryptoPassed pw -> pw  -- TODO: This generates an Element, how do we find the corresponding scalar?
    CryptoFailed err -> panic ("Could not generate password: " <> show err)

createSessionKey :: sideID -> sideID -> Element Curve_P521R1 -> Element Curve_P521R1 -> Element Curve_P521R1 -> ByteString
createSessionKey = notImplemented -- You'll have to figure this out. Some sort of hash of the inputs.
@

=== Side A

@
runSpake2 = do
  let params = Math.Params group m n
  let spake2 = Math.Spake2 params password
  spake2Exchange <- Math.startSpake2 spake2
  let outbound = Math.computeOutboundMessage spake2Exchange
  sendOutboundMessage outbound
  -- NOTE: We could wait for this before sending the outbound. Depends on the
  -- network protocol you're arranging with your application.
  inbound <- waitForInboundMessage
  let key = Math.generateKeyMaterial spake2Exchange inbound
  createSessionKey sideA sideB outbound inbound key password
@

=== Side B

The same as Side A, but @n@ and @m@ are swapped around.

@
runSpake2 = do
  let params = Math.Params group n m
  let spake2 = Math.Spake2 params password
  inbound <- waitForInboundMessage
  spake2Exchange <- Math.startSpake2 spake2
  let outbound = Math.computeOutboundMessage spake2Exchange
  sendOutboundMessage outbound
  let key = Math.generateKeyMaterial spake2Exchange inbound
  createSessionKey sideA sideB outbound inbound key password
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

import Protolude hiding (group)

import Crypto.Random.Types (MonadRandom(..))

import Crypto.Spake2.Groups (Group(..), KeyPair(..))

-- | The parameters of the SPAKE2 protocol. The other side needs to be using
-- the same values, but with swapped values for 'ourBlind' and 'theirBlind'.
data Params group
  = Params
  { group :: group -- ^ The cyclic group used for encrypting keys
  , ourBlind :: Element group -- ^ The "blind" we use when sending out values. Side A refers to this as \(M\) in the protocol description.
  , theirBlind :: Element group -- ^ The "blind" the other side uses when sending values. Side A refers to this as \(N\) in the protocol description.
  }

-- | An instance of the SPAKE2 protocol. This represents one side of the protocol.
data Spake2 group
  = Spake2
  { params :: Params group
  , password :: Scalar group
  }

-- | A SPAKE2 exchange that has been initiated.
data Spake2Exchange group
  = Started
  { spake2 :: Spake2 group -- ^ Description of the specific instance of the
                           -- SPAKE2 protocol we are using. Parameters,
                           -- password, and group must be the same for this to
                           -- work.
  , xy :: KeyPair group -- ^ Arbitrary element and scalar chosen by this side of the exchange.
                        -- It is kept secret, and is only used to negotiate an exchange.
                        -- A "blinded" form is sent to the other side of the protocol.
  }

-- | Initiate the SPAKE2 exchange. Generates a secret (@xy@) that will be held
-- by this side, and transmitted to the other side in "blinded" form.
startSpake2 :: (Group group, MonadRandom randomly) => Spake2 group -> randomly (Spake2Exchange group)
startSpake2 spake2' = Started spake2' <$> generateElement (group . params $ spake2')

-- | Determine the element (either \(X^{\star}\) or \(Y^{\star}\)) to send to the other side.
computeOutboundMessage :: Group group => Spake2Exchange group -> Element group
computeOutboundMessage Started{spake2 = Spake2{params = Params{group, ourBlind}, password}, xy} =
  elementAdd group (keyPairPublic xy) (scalarMultiply group password ourBlind)

-- | Generate key material, \(K\), given a message from the other side (either
-- \(Y^{\star}\) or \(X^{\star}\)).
--
-- This key material is the last piece of input required to make the session
-- key, \(SK\), which should be generated as:
--
--   \[SK \leftarrow H(A, B, X^{\star}, Y^{\star}, K, pw)\]
--
-- Where:
--
-- * \(H\) is a hash function
-- * \(A\) identifies the initiating side
-- * \(B\) identifies the receiving side
-- * \(X^{star}\) is the outbound message from the initiating side
-- * \(Y^{star}\) is the outbound message from the receiving side
-- * \(K\) is the result of this function
-- * \(pw\) is the password (this is what makes it SPAKE2, not SPAKE1)
generateKeyMaterial
  :: Group group
  => Spake2Exchange group  -- ^ An initiated SPAKE2 exchange
  -> Element group  -- ^ The outbound message from the other side (i.e. inbound to us)
  -> Element group -- ^ The final piece of key material to generate the session key.
generateKeyMaterial Started{spake2 = Spake2{params = Params{group, theirBlind}, password}, xy} inbound =
  scalarMultiply group (keyPairPrivate xy) (elementSubtract group inbound (scalarMultiply group password theirBlind))
