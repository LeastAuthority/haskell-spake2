{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NamedFieldPuns #-}

{-|
Module: Crypto.Spake2.Math
Description: The mathematical implementation of SPAKE2.

This module ignores everything about networks, bytes, encoding, hash functions, and so forth.
All it does is provide the mathematical building blocks for SPAKE2,
as per [Simple Password-Based Encrypted Key Exchange Protocols](http://www.di.ens.fr/~pointche/Documents/Papers/2005_rsa.pdf)
by Michel Abdalla and David Pointcheval.

== How it works

=== Preliminaries

Let's say we have two users, user A and user B.
They have already agreed on the following public information:

 * cyclic group, \(G\) of prime order, \(p\)
 * generating element \(g \in G\), such that \(g \neq 1\)
 * hash algorithm to use, \(H\)

If the connection is asymmetric
(e.g. if user A is a client and user B is a server),
then they will also have:

 * two arbitrary elements in \(M, N \in G\), where \(M\) is associated with
   user A and \(N\) with user B.

If the connection is symmetric
(e.g. if user A and B are arbitrary peers),
then they will instead have:

 * a single arbitrary element \(S \in G\)

The discrete log of these arbitrary elements must be difficult to guess.

And, they also have a secret password,
which in practice will be an arbitrary byte string,
but for the purposes of this module is an arbitrary /scalar/ in the group
that is a shared secret between both parties
(see "Crypto.Spake2.Groups" for more information on scalars).

=== The protocol

/This is derived from the paper linked above./

One side, A, initiates the exchange.
They draw a random scalar, \(x\), and matching element, \(X\), from the group.
They then "blind" \(X\) by adding it to \(M\) multiplied by the password in scalar form.
Call this \(X^{\star}\).

\[X^{\star} \leftarrow X \cdot M^{pw}\]

to the other side, side B.

Side B does the same thing,
except they use \(N\) instead of \(M\) to blind the result,
and they call it \(Y\) instead of \(X\).

\[Y^{\star} \leftarrow Y \cdot N^{pw}\]

After side A receives \(Y^{\star}\),
it calculates \(K_A\),
which is the last missing input in calculating the session key.

\[K_A \leftarrow (Y^{\star}/N^{pw})^x\]

That is, \(K_A\) is \(Y^{\star}\) subtracted from \(N\) scalar multiplied by \(pw\),
all of which is scalar multiplied by \(x\).

Side B likewise calculates:

\[K_B \leftarrow (X^{\star}/M^{pw})^y\]

If both parties were honest and knew the password,
the keys will be the same on both sides.
That is:

\[K_A = K_B\]

=== How to use the keys

The keys \(K_A\) and \(K_B\) are not enough to securely encrypt a session.
They must be used as input to create a session key.

Constructing a session key is beyond the scope of this module.
See 'createSessionKey' for more information.

-}

module Crypto.Spake2.Math
  ( Spake2(..)
  , Params(..)
  , startSpake2
  , Spake2Exchange
  , computeOutboundMessage
  , generateKeyMaterial
  ) where

import Protolude hiding (group)

import Crypto.Random.Types (MonadRandom(..))

import Crypto.Spake2.Group (Group(..), KeyPair(..))

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
