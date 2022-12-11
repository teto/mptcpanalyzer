{-# LANGUAGE ScopedTypeVariables #-}
module MptcpAnalyzer.MapSpec (
spec
) where
-- import           Test.Tasty
-- import           Test.Tasty.HUnit
import Data.Maybe (fromJust)
import Distribution.Simple.Utils (TempFileOptions(..), withTempFileEx)
import Net.IP
import Net.IPv4 (localhost)
import Net.Tcp.Connection
import Polysemy (Final, Members, Sem, runFinal)
import qualified Polysemy as P
import qualified Polysemy.Embed as P
import qualified Polysemy.IO as P
import qualified Polysemy.Internal as P
import Polysemy.Log (Log)
import qualified Polysemy.Log as Log
import Polysemy.Log.Colog (interpretLogStdout)
import System.Exit (ExitCode(ExitSuccess))
import System.IO
import Test.Hspec
import Test.QuickCheck hiding (Success)
import Tshark.Main

import Data.Either (fromRight)
import Frames.Frame (Frame)
import MptcpAnalyzer.ArtificialFields
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Loader (loadPcapIntoFrame)
import MptcpAnalyzer.Map
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Stream
import MptcpAnalyzer.Types
import Utils

cacheConfig :: CacheConfig
cacheConfig = CacheConfig {
  cacheFolder = "/tmp"
  , cacheEnabled = False
}


loadTestFrames :: IO (FrameFiltered TcpConnection Packet, Frame Packet)
loadTestFrames = do

  aframes <- P.runM
    $ interpretLogStdout
    $ runCache cacheConfig
      runTests
  return aframes


runTests :: (Members '[P.Embed IO, Log, Cache] r) => Sem r (FrameFiltered TcpConnection Packet, Frame Packet)
runTests = do
  -- :: Either String (Frame Packet)
  eFrame1 <- loadPcapIntoFrame defaultTsharkPrefs "examples/client_2_cleaned.pcapng"
  eFrame2 <- loadPcapIntoFrame defaultTsharkPrefs "examples/server_2_cleaned.pcapng"

  frame2 <- case eFrame2 of
    Left err -> error err
    Right frame -> return frame

  (aframe :: FrameFiltered TcpConnection Packet) <- case buildFrameFromStreamId (fromRight (error "should not happen") eFrame1) (StreamId 0) of
    Left err -> error err
    Right aframe -> return aframe

  return (aframe, frame2)

-- TODO this should be part of a golden test with tasty instead
expectedMappings = [
  (TcpConnection {clientIp = ipv4 10 0 0 1, serverIp = ipv4 10 0 0 2, conclientPort = 33782, serverPort = 5201, streamId = StreamId 0},40)
  ,(TcpConnection {clientIp = ipv4 10 0 0 1, serverIp = ipv4 10 0 0 2, conclientPort = 33784, serverPort = 5201, streamId = StreamId 1},30)
  ,(TcpConnection {clientIp = ipv4 10 0 0 1, serverIp = ipv4 11 0 0 2, conclientPort = 54595, serverPort = 5201, streamId = StreamId 2},20)
  ,(TcpConnection {clientIp = ipv4 10 0 0 1, serverIp = ipv4 11 0 0 2, conclientPort = 57491, serverPort = 5201, streamId = StreamId 3},20)
  ,(TcpConnection {clientIp = ipv4 11 0 0 1, serverIp = ipv4 10 0 0 2, conclientPort = 35589, serverPort = 5201, streamId = StreamId 6},20)
  ,(TcpConnection {clientIp = ipv4 11 0 0 1, serverIp = ipv4 10 0 0 2, conclientPort = 50007, serverPort = 5201, streamId = StreamId 7},20)
  ,(TcpConnection {clientIp = ipv4 11 0 0 1, serverIp = ipv4 11 0 0 2, conclientPort = 50077, serverPort = 5201, streamId = StreamId 5},10)]

spec :: Spec
spec = describe "Checking connection mapper" $ do
  before loadTestFrames $ it "test" $ \(aframe, frame1) ->
    mapTcpConnection aframe frame1 `shouldBe` expectedMappings
    -- pendingWith "test"
  -- TODO check
  -- mapTcpConnection

