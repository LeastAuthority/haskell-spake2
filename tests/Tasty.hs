module Main
  ( main
  ) where

import Protolude

import Test.Tasty (defaultMain, testGroup)

import qualified Spake2

main :: IO ()
main = sequence tests >>= defaultMain . testGroup "Spake2"
  where
    tests =
      [ Spake2.tests
      ]
