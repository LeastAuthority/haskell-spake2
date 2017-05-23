{-# LANGUAGE FlexibleContexts #-}
-- | Entrypoint for testing interoperability.
--
-- Interoperability harness lives at <https://github.com/leastauthority/spake2-interop-test>
--
-- Any entry point for the harness needs to:
--  - take everything it needs as command-line parameters
--  - print the outbound message to stdout
--  - read the inbound message from stdin
--  - print the session key
--  - terminate
--
-- Much of the code in here will probably move to the library as we figure out
-- what we need to do to implement the protocol properly.

module Main (main) where

import Protolude hiding (group)

import Crypto.Hash (SHA256(..))
import Options.Applicative
import System.IO (hGetLine, hPutStrLn)

import qualified Crypto.Spake2 as Spake2
import Crypto.Spake2
  ( Password
  , Protocol
  , SideID(..)
  , makeSymmetricProtocol
  , makeAsymmetricProtocol
  , createSessionKey
  , makePassword
  , computeOutboundMessage
  , generateArbitraryElement
  , generateKeyMaterial
  , extractElement
  , startSpake2
  , elementToMessage
  , formatError
  )
import Crypto.Spake2.Groups (Group(..), IntegerAddition(..))


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
    passwordParser = makePassword . toS <$> str


-- | Terminate the test with a failure, printing a message to stderr.
abort :: HasCallStack => Text -> IO ()
abort message = do
  hPutStrLn stderr $ toS ("ERROR: " <> message)
  exitWith (ExitFailure 1)


runInteropTest
  :: (HasCallStack, Group group)
  => Protocol group SHA256
  -> Password
  -> Handle
  -> Handle
  -> IO ()
runInteropTest protocol password inH outH = do
  spake2 <- startSpake2 protocol password
  let outElement = computeOutboundMessage spake2
  hPutStrLn outH (encodeForStdout (elementToMessage protocol outElement))
  inMsg <- hGetLine inH
  case extractElement protocol (decodeFromStdin inMsg) of
    Left err -> abort $ "Could not handle incoming message (msg = " <> show inMsg <> "): " <> formatError err
    Right inElement -> do
      -- TODO: This is wrong, because it doesn't handle A/B properly.
      let key = generateKeyMaterial spake2 inElement
      let sessionKey = createSessionKey protocol inElement outElement key password
      hPutStrLn outH (encodeForStdout sessionKey)

  where
    -- TODO: Somehow hex encode like Python
    encodeForStdout = toS
    decodeFromStdin = toS


makeProtocolFromSide :: Side -> Protocol IntegerAddition SHA256
makeProtocolFromSide side =
  case side of
    SideA -> makeAsymmetricProtocol hashAlg group m n idA idB Spake2.SideA
    SideB -> makeAsymmetricProtocol hashAlg group m n idA idB Spake2.SideB
    Symmetric -> makeSymmetricProtocol hashAlg group s idSymmetric
  where
    hashAlg = SHA256
    group = IntegerAddition 7
    m = generateArbitraryElement group ("m" :: ByteString)
    n = generateArbitraryElement group ("n" :: ByteString)
    s = generateArbitraryElement group ("s" :: ByteString)
    idA = SideID ""
    idB = SideID ""
    idSymmetric = SideID ""

main :: IO ()
main = do
  Config side password <- execParser opts
  print side
  let protocol = makeProtocolFromSide side
  runInteropTest protocol password stdin stdout
  exitSuccess
  where
    opts = info (helper <*> configParser)
           (fullDesc <>
            header "interop-entrypoint - tool to help test SPAKE2 interop")
