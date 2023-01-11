module Spake2 (tests) where

import Protolude hiding (group)
import Test.Tasty (TestTree)
import Test.Tasty.Hspec (testSpec)

import Test.Hspec (describe, it)
import Test.Hspec.Expectations (shouldBe, shouldNotBe)


import Crypto.Hash (SHA256(..))
import qualified Crypto.Spake2 as Spake2
import qualified Crypto.Spake2.Group as Group
import Crypto.Spake2.Groups (Ed25519(..))

tests :: IO TestTree
tests = testSpec "Spake2" $ do
  describe "Asymmetric protocol" $ do
    it "Produces matching session keys when passwords match" $ do
      let password = Spake2.makePassword "abc"
      let idA = Spake2.SideID "side-a"
      let idB = Spake2.SideID "side-b"
      let protocolA = defaultAsymmetricProtocol idA idB Spake2.SideA
      let protocolB = defaultAsymmetricProtocol idA idB Spake2.SideB
      (Right aSessionKey, Right bSessionKey) <- (protocolA, password) `versus` (protocolB, password)
      aSessionKey `shouldBe` bSessionKey

    it "Produces differing session keys when passwords do not match" $ do
      let password1 = Spake2.makePassword "abc"
      let password2 = Spake2.makePassword "cba"
      let idA = Spake2.SideID ""
      let idB = Spake2.SideID ""
      let protocolA = defaultAsymmetricProtocol idA idB Spake2.SideA
      let protocolB = defaultAsymmetricProtocol idA idB Spake2.SideB
      (Right aSessionKey, Right bSessionKey) <- (protocolA, password1) `versus` (protocolB, password2)
      aSessionKey `shouldNotBe` bSessionKey

  describe "Symmetric protocol" $ do
    it "Produces matching session keys when passwords match" $ do
      let password = Spake2.makePassword "abc"
      let protocol = defaultSymmetricProtocol (Spake2.SideID "")
      (Right sessionKey1, Right sessionKey2) <- (protocol, password) `versus` (protocol, password)
      sessionKey1 `shouldBe` sessionKey2

    it "Produces differing session keys when passwords do not match" $ do
      let password1 = Spake2.makePassword "abc"
      let password2 = Spake2.makePassword "cba"
      let protocol = defaultSymmetricProtocol (Spake2.SideID "")
      (Right sessionKey1, Right sessionKey2) <- (protocol, password1) `versus` (protocol, password2)
      sessionKey1 `shouldNotBe` sessionKey2

  where
    defaultAsymmetricProtocol = Spake2.makeAsymmetricProtocol SHA256 group m n
    m = Group.arbitraryElement group ("M" :: ByteString)
    n = Group.arbitraryElement group ("N" :: ByteString)

    defaultSymmetricProtocol = Spake2.makeSymmetricProtocol SHA256 group s
    s = Group.arbitraryElement group ("symmetric" :: ByteString)

    group = Ed25519

    -- | Run protocol A with password A against protocol B with password B.
    versus (protocolA, passwordA) (protocolB, passwordB) = do
      aOutVar <- newEmptyMVar
      bOutVar <- newEmptyMVar
      concurrently
        (Spake2.spake2Exchange protocolA passwordA (putMVar aOutVar) (Right <$> readMVar bOutVar))
        (Spake2.spake2Exchange protocolB passwordB (putMVar bOutVar) (Right <$> readMVar aOutVar))
