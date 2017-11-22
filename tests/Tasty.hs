module Main
  ( main
  ) where

import Protolude

import Test.Tasty (defaultMain, testGroup)

import qualified Spake2
import qualified Groups
import qualified Integration

main :: IO ()
main = sequence tests >>= defaultMain . testGroup "Spake2"
  where
    tests =
      [ Spake2.tests
      , Groups.tests
      , Integration.tests
      ]
