{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE NamedFieldPuns #-}
{-|
Module: Crypto.Spake2.Groups
Description: Implementation for mathematical groups
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

