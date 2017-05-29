module Spake2 (tests) where

import Protolude hiding (group)
import Test.Tasty (TestTree)
import Test.Tasty.Hspec (testSpec, describe, it, shouldBe, shouldNotBe)

import Crypto.Hash (SHA256(..))
import qualified Crypto.Spake2 as Spake2
import qualified Crypto.Spake2.Group as Group
import Crypto.Spake2.Groups (Ed25519(..))

tests :: IO TestTree
tests = testSpec "Spake2" $ do
  describe "Asymmetric protocol" $ do
    it "Produces matching session keys when passwords match" $ do
      let password = Spake2.makePassword "abc"
      let hashAlg = SHA256
      let group = Ed25519
      let m = Group.arbitraryElement group ("M" :: ByteString)
      let n = Group.arbitraryElement group ("N" :: ByteString)
      let idA = Spake2.SideID ""
      let idB = Spake2.SideID ""
      let protocolA = Spake2.makeAsymmetricProtocol hashAlg group m n idA idB Spake2.SideA
      let protocolB = Spake2.makeAsymmetricProtocol hashAlg group m n idA idB Spake2.SideB
      sideA <- Spake2.startSpake2 protocolA password
      sideB <- Spake2.startSpake2 protocolB password
      let aOut = Spake2.computeOutboundMessage sideA
      let bOut = Spake2.computeOutboundMessage sideB
      let aKey = Spake2.generateKeyMaterial sideA bOut
      let bKey = Spake2.generateKeyMaterial sideB aOut
      let aSessionKey = Spake2.createSessionKey protocolA aOut bOut aKey password
      let bSessionKey = Spake2.createSessionKey protocolA aOut bOut bKey password
      aSessionKey `shouldBe` bSessionKey
    it "Produces differing session keys when passwords do not match" $ do
      let password1 = Spake2.makePassword "abc"
      let password2 = Spake2.makePassword "cba"
      let hashAlg = SHA256
      let group = Ed25519
      let m = Group.arbitraryElement group ("M" :: ByteString)
      let n = Group.arbitraryElement group ("N" :: ByteString)
      let idA = Spake2.SideID ""
      let idB = Spake2.SideID ""
      let protocolA = Spake2.makeAsymmetricProtocol hashAlg group m n idA idB Spake2.SideA
      let protocolB = Spake2.makeAsymmetricProtocol hashAlg group m n idA idB Spake2.SideB
      sideA <- Spake2.startSpake2 protocolA password1
      sideB <- Spake2.startSpake2 protocolB password2
      let aOut = Spake2.computeOutboundMessage sideA
      let bOut = Spake2.computeOutboundMessage sideB
      let aKey = Spake2.generateKeyMaterial sideA bOut
      let bKey = Spake2.generateKeyMaterial sideB aOut
      let aSessionKey = Spake2.createSessionKey protocolA aOut bOut aKey password1
      let bSessionKey = Spake2.createSessionKey protocolA aOut bOut bKey password2
      aSessionKey `shouldNotBe` bSessionKey
  describe "Symmetric protocol" $ do
    it "Produces matching session keys when passwords match" $ do
      let password = Spake2.makePassword "abc"
      let hashAlg = SHA256
      let group = Ed25519
      let s = Group.arbitraryElement group ("M" :: ByteString)
      let idSymmetric = Spake2.SideID ""
      let protocol1 = Spake2.makeSymmetricProtocol hashAlg group s idSymmetric
      let protocol2 = Spake2.makeSymmetricProtocol hashAlg group s idSymmetric
      side1 <- Spake2.startSpake2 protocol1 password
      side2 <- Spake2.startSpake2 protocol2 password
      let out1 = Spake2.computeOutboundMessage side1
      let out2 = Spake2.computeOutboundMessage side2
      let key1 = Spake2.generateKeyMaterial side1 out2
      let key2 = Spake2.generateKeyMaterial side2 out1
      let sessionKey1 = Spake2.createSessionKey protocol1 out1 out2 key1 password
      let sessionKey2 = Spake2.createSessionKey protocol2 out1 out2 key2 password
      sessionKey1 `shouldBe` sessionKey2
    it "Produces differing session keys when passwords do not match" $ do
      let password1 = Spake2.makePassword "abc"
      let password2 = Spake2.makePassword "cba"
      let hashAlg = SHA256
      let group = Ed25519
      let s = Group.arbitraryElement group ("M" :: ByteString)
      let idSymmetric = Spake2.SideID ""
      let protocol1 = Spake2.makeSymmetricProtocol hashAlg group s idSymmetric
      let protocol2 = Spake2.makeSymmetricProtocol hashAlg group s idSymmetric
      side1 <- Spake2.startSpake2 protocol1 password1
      side2 <- Spake2.startSpake2 protocol2 password2
      let out1 = Spake2.computeOutboundMessage side1
      let out2 = Spake2.computeOutboundMessage side2
      let key1 = Spake2.generateKeyMaterial side1 out2
      let key2 = Spake2.generateKeyMaterial side2 out1
      let sessionKey1 = Spake2.createSessionKey protocol1 out1 out2 key1 password1
      let sessionKey2 = Spake2.createSessionKey protocol2 out1 out2 key2 password2
      sessionKey1 `shouldNotBe` sessionKey2
