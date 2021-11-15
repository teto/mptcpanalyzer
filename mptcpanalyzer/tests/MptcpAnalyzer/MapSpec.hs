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

cacheConfig :: CacheConfig
cacheConfig = CacheConfig {
  cacheFolder = "/tmp"
  , cacheEnabled = False
}


loadAFrame :: IO (FrameFiltered TcpConnection Packet, Frame Packet)
loadAFrame = do

  aframe <- P.runM
    $ interpretLogStdout
    $ runCache cacheConfig
      runTests
  return aframe


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


spec :: Spec
spec = describe "Checking connection mapper" $ do
  before loadAFrame $ it "test" $ \aframe ->
    pendingWith "test"
  -- TODO check
  -- mapTcpConnection

