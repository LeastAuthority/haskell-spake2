{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE NamedFieldPuns #-}

{-|
Module: Crypto.Spake2
Description: Implementation of SPAKE2 key exchange protocol

Say that you and someone else share a secret password, and you want to use
this password to arrange some secure channel of communication. You want:

 * to know that the other party also knows the secret password (maybe
   they're an imposter!)
 * the password to be secure against offline dictionary attacks
 * probably some other things

SPAKE2 is an algorithm for agreeing on a key exchange that meets these
criteria. See [Simple Password-Based Encrypted Key Exchange
Protocols](http://www.di.ens.fr/~pointche/Documents/Papers/2005_rsa.pdf) by
Michel Abdalla and David Pointcheval for more details.

== How it works

=== Preliminaries

Let's say we have two users, user A and user B. They have already agreed on
the following public information:

 * cyclic group, \(G\) of prime order, \(p\)
 * generating element \(g \in G\), such that \(g \neq 1\)
 * hash algorithm to use, \(H\)

__XXX__: jml's current understanding is that all of this is provided by something
like 'Crypto.ECC.Curve_X25519', and generally anything that implements the
'Crypto.ECC.EllipticCurve' typeclass in a sane way. It is possible that this
typeclass is insufficient.

__TODO__: describe points and scalars in relation to this group.


If the connection is asymmetric (e.g. if user A is a client and user B is a
server), then they will also have:

 * two arbitrary elements in \(M, N \in G\), where \(M\) is associated with
   user A and \(N\) with user B.

If the connection is symmetric (e.g. if user A and B are arbitrary peers),
then they will instead have:

 * a single arbitrary element \(S \in G\)

__XXX__: jml's current understanding is that these are indeed arbitrarily chosen,
and are part of the SPAKE2 protocol specialised to a particular use case. i.e.
that these are /not/ provided by 'EllipticCurve' or the like.

And, they also have a secret password, which in theory is an arbitrary bit
string, but for the purposes of this module is an arbitrary /byte/ string.

This password is mapped to a /scalar/ in group \(G\), in a way that's mutually
agreed to both parties. The means of mapping may be public, but the actual
mapped value /must/ be secret.


=== Protocol

One side, A, initiates the exchange. They draw a random point, \(X\) from the
group.

|-}

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

{-
computeOutboundMessage :: EllipticCurveArith curve => Started curve -> Point curve -> outbound
computeOutboundMessage Started{spake2, xy} blinding =
  notImplemented
-}
