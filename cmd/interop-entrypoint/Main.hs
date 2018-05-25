{-# LANGUAGE FlexibleContexts #-}
-- | Entrypoint for testing interoperability.
--
-- Interoperability harness lives at <https://github.com/leastauthority/spake2-interop-test>
--
-- Any entry point for the harness needs to:
--  - take everything it needs as command-line parameters
--  - print the outbound message to stdout, base16-encoded
--  - read the inbound message from stdin, base16-encoded
--  - print the session key, base16-encoded
--  - terminate
--
-- Much of the code in here will probably move to the library as we figure out
-- what we need to do to implement the protocol properly.

module Main (main) where

import Protolude hiding (group)

import Crypto.Hash (SHA256(..))
import Data.ByteArray.Encoding (convertFromBase, convertToBase, Base(Base16))
import Options.Applicative
import System.IO (hFlush, hGetLine)

import qualified Crypto.Spake2 as Spake2
import Crypto.Spake2
  ( Password
  , Protocol
  , SideID(..)
  , makeSymmetricProtocol
  , makeAsymmetricProtocol
  , makePassword
  , spake2Exchange
  )
import Crypto.Spake2.Group (AbelianGroup, Group(..))
import Crypto.Spake2.Groups (Ed25519(..))


data Config = Config Side Password deriving (Eq, Ord)

data Side = SideA | SideB | Symmetric deriving (Eq, Ord, Show)

configParser :: Parser Config
configParser =
  Config
    <$> argument sideParser (metavar "SIDE")
    <*> argument passwordParser (metavar "PASSWORD")
  where
    sideParser = eitherReader $ \s ->
      case s of
        "A" -> pure SideA
        "B" -> pure SideB
        "Symmetric" -> pure Symmetric
        unknown -> throwError $ "Unrecognized side: " <> unknown
    passwordParser = makePassword . toS <$> (str :: ReadM Text)


-- | Terminate the test with a failure, printing a message to stderr.
abort :: HasCallStack => Text -> IO ()
abort message = do
  hPutStrLn stderr ("ERROR: " <> message)
  exitWith (ExitFailure 1)


runInteropTest
  :: (HasCallStack, AbelianGroup group)
  => Protocol group SHA256
  -> Password
  -> Handle
  -> Handle
  -> IO ()
runInteropTest protocol password inH outH = do
  sessionKey' <- spake2Exchange protocol password output input
  case sessionKey' of
    Left err -> abort $ show err
    Right sessionKey -> output sessionKey
  where
    output :: ByteString -> IO ()
    output message = do
      hPutStrLn outH (convertToBase Base16 message :: ByteString)
      hFlush outH

    input :: IO (Either Text ByteString)
    input = do
      line <- hGetLine inH
      case convertFromBase Base16 (toS line :: ByteString) of
        Left err -> pure . Left . toS $ "Could not decode line (reason: " <> err <> "): " <> show line
        Right bytes -> pure (Right bytes)


makeProtocolFromSide :: Side -> Protocol Ed25519 SHA256
makeProtocolFromSide side =
  case side of
    SideA -> makeAsymmetricProtocol hashAlg group m n idA idB Spake2.SideA
    SideB -> makeAsymmetricProtocol hashAlg group m n idA idB Spake2.SideB
    Symmetric -> makeSymmetricProtocol hashAlg group s idSymmetric
  where
    hashAlg = SHA256
    group = Ed25519
    m = arbitraryElement group ("M" :: ByteString)
    n = arbitraryElement group ("N" :: ByteString)
    s = arbitraryElement group ("symmetric" :: ByteString)
    idA = SideID ""
    idB = SideID ""
    idSymmetric = SideID ""

main :: IO ()
main = do
  Config side password <- execParser opts
  let protocol = makeProtocolFromSide side
  runInteropTest protocol password stdin stdout
  exitSuccess
  where
    opts = info (helper <*> configParser)
           (fullDesc <>
            header "interop-entrypoint - tool to help test SPAKE2 interop")
