{-# LANGUAGE ScopedTypeVariables #-}
module MptcpAnalyzer.MapSpec (
spec
) where
-- import           Test.Tasty
-- import           Test.Tasty.HUnit
import Distribution.Simple.Utils (TempFileOptions(..), withTempFileEx)
import Net.IP
import Net.IPv4 (localhost)
import Net.Tcp.Connection
import System.Exit (ExitCode(ExitSuccess))
import System.IO
import Test.Hspec
import Test.QuickCheck hiding (Success)
import Tshark.Main
import Data.Maybe (fromJust)
import Polysemy (Final, Members, Sem, runFinal)
import qualified Polysemy as P
import qualified Polysemy.Embed as P
import qualified Polysemy.IO as P
import qualified Polysemy.Internal as P
import Polysemy.Log (Log)
import qualified Polysemy.Log as Log
import Polysemy.Log.Colog (interpretLogStdout)

import MptcpAnalyzer.Types
import MptcpAnalyzer.ArtificialFields
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Stream
import MptcpAnalyzer.Cache
import Data.Either (fromRight)
import MptcpAnalyzer.Loader (loadPcapIntoFrame)
import Frames.Frame (Frame)
import MptcpAnalyzer.Map
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
expectedMappings = [(TcpConnection {conTcpClientIp = ipv4 10 0 0 1, conTcpServerIp = ipv4 10 0 0 2, conTcpClientPort = 33782, conTcpServerPort = 5201, conTcpStreamId = StreamId 0},40),(TcpConnection {conTcpClientIp = ipv4 10 0 0 1, conTcpServerIp = ipv4 10 0 0 2, conTcpClientPort = 33784, conTcpServerPort = 5201, conTcpStreamId = StreamId 1},30),(TcpConnection {conTcpClientIp = ipv4 10 0 0 1, conTcpServerIp = ipv4 11 0 0 2, conTcpClientPort = 54595, conTcpServerPort = 5201, conTcpStreamId = StreamId 2},20),(TcpConnection {conTcpClientIp = ipv4 10 0 0 1, conTcpServerIp = ipv4 11 0 0 2, conTcpClientPort = 57491, conTcpServerPort = 5201, conTcpStreamId = StreamId 3},20),(TcpConnection {conTcpClientIp = ipv4 11 0 0 1, conTcpServerIp = ipv4 10 0 0 2, conTcpClientPort = 35589, conTcpServerPort = 5201, conTcpStreamId = StreamId 6},20),(TcpConnection {conTcpClientIp = ipv4 11 0 0 1, conTcpServerIp = ipv4 10 0 0 2, conTcpClientPort = 50007, conTcpServerPort = 5201, conTcpStreamId = StreamId 7},20),(TcpConnection {conTcpClientIp = ipv4 11 0 0 1, conTcpServerIp = ipv4 11 0 0 2, conTcpClientPort = 50077, conTcpServerPort = 5201, conTcpStreamId = StreamId 5},10)]

spec :: Spec
spec = describe "Checking connection mapper" $ do
  before loadTestFrames $ it "test" $ \(aframe, frame1) ->
    mapTcpConnection aframe frame1 `shouldBe` expectedMappings
    -- pendingWith "test"
  -- TODO check
  -- mapTcpConnection

