module Spake2 (tests) where

import Protolude
import Test.Tasty (TestTree)
import Test.Tasty.Hspec (testSpec, describe, it, shouldBe)

import qualified Crypto.Spake2 as Spake2

tests :: IO TestTree
tests = testSpec "Spake2" $ do
  describe "something" $
    it "should do things" $
      Spake2.something (2 :: Int) `shouldBe` 2
