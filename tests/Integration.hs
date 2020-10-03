module Integration (tests) where

import Protolude hiding (stdin, stdout, toS)
import Protolude.Conv (toS)

import Crypto.Hash (SHA256(..))
import Data.ByteArray.Encoding (convertFromBase, convertToBase, Base(Base16))
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as Char8
import qualified System.IO as IO
import qualified System.Process as Process
import Test.Tasty (TestTree)
import Test.Tasty.Hspec (testSpec, describe, it, shouldBe)

import qualified Crypto.Spake2 as Spake2
import Crypto.Spake2.Group (Group(arbitraryElement))
import Crypto.Spake2.Groups (Ed25519(..))

import qualified Paths_spake2

tests :: IO TestTree
tests = testSpec "Integration" $
  describe "python-spake2" $ do
    it "Generates the same SPAKE2 session key (symmetric)" $ do
      let sideID = "treebeard"
      let password = "mellon"
      let protocol = Spake2.makeSymmetricProtocol SHA256 Ed25519 blindS (Spake2.SideID sideID)
      exchangeWithPython protocol password
        [ "--side=S"
        , "--side-id=" <> toS sideID
        ]

    it "Generates the same SPAKE2 session key (asymmetric, we are side B)" $ do
      let ourSideID = "alliance"
      let theirSideID = "horde"
      let password = "mellon"
      let protocol = Spake2.makeAsymmetricProtocol SHA256 Ed25519 blindA blindB (Spake2.SideID theirSideID) (Spake2.SideID ourSideID) Spake2.SideB
      exchangeWithPython protocol password
        [ "--side=A"
        , "--side-id=" <> toS theirSideID
        , "--other-side-id=" <> toS ourSideID
        ]

    it "Generates the same SPAKE2 session key (asymmetric, we are side A)" $ do
      let ourSideID = "alliance"
      let theirSideID = "horde"
      let password = "mellon"
      let protocol = Spake2.makeAsymmetricProtocol SHA256 Ed25519 blindA blindB (Spake2.SideID ourSideID) (Spake2.SideID theirSideID) Spake2.SideA
      exchangeWithPython protocol password
        [ "--side=B"
        , "--side-id=" <> toS theirSideID
        , "--other-side-id=" <> toS ourSideID
        ]

  where
    send h x = Char8.hPutStrLn h (convertToBase Base16 x)
    receive h = convertFromBase Base16 <$> ByteString.hGetLine h
    blindA = arbitraryElement Ed25519 ("M" :: ByteString)
    blindB = arbitraryElement Ed25519 ("N" :: ByteString)
    blindS = arbitraryElement Ed25519 ("symmetric" :: ByteString)

    exchangeWithPython protocol password args = do
      scriptExe <- Paths_spake2.getDataFileName "tests/python/spake2_exchange.py"
      let testScript = (Process.proc "python" (scriptExe:("--code=" <> toS password):args))
                       { Process.std_in = Process.CreatePipe
                       , Process.std_out = Process.CreatePipe
                       , Process.std_err = Process.Inherit  -- So we get stack traces printed during test runs.
                       }
      Process.withCreateProcess testScript $
        \(Just stdin) (Just stdout) _stderr ph -> do
          -- The inter-process protocol is line-based.
          IO.hSetBuffering stdin IO.LineBuffering
          IO.hSetBuffering stdout IO.LineBuffering
          IO.hSetBuffering stderr IO.LineBuffering
          (do Right sessionKey <- Spake2.spake2Exchange protocol (Spake2.makePassword password) (send stdin) (receive stdout)
              theirSpakeKey <- ByteString.hGetLine stdout
              theirSpakeKey `shouldBe` convertToBase Base16 sessionKey) `finally` Process.waitForProcess ph
