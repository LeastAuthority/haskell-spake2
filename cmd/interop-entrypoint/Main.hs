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

import Protolude

import Crypto.ECC (EllipticCurve(..), Curve_X25519)
import Crypto.Hash (SHA256)
import Options.Applicative
import System.IO (hGetLine, hPutStrLn)

import Crypto.Spake2
  ( Password
  , Protocol
  , createSessionKey
  , makePassword
  )


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


runInteropTest :: (HasCallStack, EllipticCurve curve) => Protocol curve SHA256 -> Password -> Handle -> Handle -> IO ()
runInteropTest protocol password inH outH = do
  let outPoint = computeOutboundMessage protocol password
  hPutStrLn outH (encode (pointToMessage protocol outPoint))
  inMsg <- hGetLine inH
  case handleInboundMessage protocol (decode inMsg) of
    Left err -> abort $ "Could not handle incoming message (msg = " <> show inMsg <> "): " <> show err
    Right (inPoint, key) -> do
      -- TODO: This is wrong, because it doesn't handle A/B properly.
      let sessionKey = createSessionKey protocol inPoint outPoint key password
      hPutStrLn outH (encode sessionKey)

  where
    -- TODO: Somehow hex encode like Python
    encode = toS
    decode = toS

    pointToMessage :: Protocol curve hashAlgorithm -> Point curve -> ByteString
    pointToMessage = notImplemented

    computeOutboundMessage :: Protocol curve hashAlgorithm -> Password -> Point curve
    computeOutboundMessage = notImplemented

    handleInboundMessage :: Protocol curve hashAlgorithm -> ByteString -> Either Text (Point curve, Point curve)
    handleInboundMessage = notImplemented


makeProtocolFromSide :: Side -> Protocol Curve_X25519 SHA256
makeProtocolFromSide _side = notImplemented


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
