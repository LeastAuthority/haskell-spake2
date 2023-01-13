{- |
Module: Crypto.Spake2.Groups
Description: Implementation of various mathematical groups

Each of these implements the 'Crypto.Spake2.Group.Group' typeclass.
-}
module Crypto.Spake2.Groups
    ( Ed25519.Ed25519 (..)
    , IntegerGroup.IntegerGroup (..)
    , IntegerGroup.makeIntegerGroup
    , IntegerGroup.i1024
    ) where

import qualified Crypto.Spake2.Groups.Ed25519 as Ed25519
import qualified Crypto.Spake2.Groups.IntegerGroup as IntegerGroup
