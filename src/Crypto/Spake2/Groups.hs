{-|
Module: Crypto.Spake2.Groups
Description: Implementation of various mathematical groups

Each of these implements the 'Crypto.Spake2.Group.Group' typeclass.
-}
module Crypto.Spake2.Groups
  ( IntegerGroup.IntegerGroup(..)
  , IntegerGroup.makeIntegerGroup
  , IntegerGroup.i1024
  -- * For testing only
  , IntegerAddition.IntegerAddition(..)
  ) where

import qualified Crypto.Spake2.Groups.IntegerAddition as IntegerAddition
import qualified Crypto.Spake2.Groups.IntegerGroup as IntegerGroup

