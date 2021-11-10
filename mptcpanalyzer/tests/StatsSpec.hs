{-# LANGUAGE ScopedTypeVariables #-}
{-
Module:  StatsSpec
Description :  Description
Maintainer  : matt
Portability : Linux

Load a pcap in chunks and check that it produces the same result
-}
module Main where
-- import           Test.Tasty
-- import           Test.Tasty.HUnit
import Frames.Exploration
import MptcpAnalyzer.Loader
import MptcpAnalyzer.Pcap
import Test.Hspec
import Test.QuickCheck hiding (Success)

import Data.Either (fromRight)
import Frames
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Stream
import MptcpAnalyzer.Types
import Net.Tcp
import Polysemy (Final, Members, Sem, runFinal)
import qualified Polysemy as P
import qualified Polysemy.Embed as P
import qualified Polysemy.IO as P
import qualified Polysemy.Internal as P
import Polysemy.Log (Log)
import qualified Polysemy.Log as Log
import Polysemy.Log.Colog (interpretLogStdout)
import qualified Polysemy.State as P
import qualified Polysemy.Trace as P
import Tshark.Main (defaultTsharkPrefs)

-- import           MptcpAnalyzer.Stats



cacheConfig :: CacheConfig
cacheConfig = CacheConfig {
  cacheFolder = "/tmp"
  , cacheEnabled = False
}

expectedForwardStats, expectedForwardStats0, expectedBackwardStats, expectedBackwardStats0, expectedForwardStatsTotal01 :: TcpUnidirectionalStats
expectedForwardStats = mempty
expectedBackwardStats = mempty
expectedForwardStats0 = mempty
expectedForwardStats1 = mempty
expectedBackwardStats0 = mempty

-- TcpUnidirectionalStats {
--       tusStartPacketId = 0 -- (frameRow frame 0) ^. packetId
--       , tusEndPacketId = 0 -- (frameRow frame (frameLength frame - 1)) ^. packetId
--       , tusNrPackets = frameLength frame
--       , tusStartTime = minTime
--       , tusEndTime = maxTime
--       -- TODO fill it
--       , tusMinSeq = minSeq

--       -- TODO should be max of seen acks
--       , tusSndUna = maxSeqRow ^. tcpSeq + fromIntegral ( maxSeqRow ^. tcpLen) :: Word32
--       , tusSndNext = maxSeqRow ^. tcpSeq + fromIntegral ( maxSeqRow ^. tcpLen ) :: Word32
--       , tusReinjectedBytes = 0


--   }

-- logs/cache
main :: IO ()
main = do

  _ <- P.runM
    $ interpretLogStdout
    $ runCache cacheConfig
      runTests
  putStrLn "finished"


splitAFrame :: FrameFiltered TcpConnection Packet -> Int -> [FrameFiltered TcpConnection Packet]
splitAFrame aframe chunkSize  =
  -- takeRows / dropRow
  go aframe []
  where
    go aframe' acc = if aframeLength aframe' < chunkSize then
        acc ++ [aframe']
      else
        go (FrameTcp (ffCon aframe') (dropRows chunkSize $ ffFrame aframe'))
           acc ++ [(FrameTcp (ffCon aframe') (takeRows chunkSize $ ffFrame aframe'))]


runTests :: (Members '[P.Embed IO, Log , Cache] r) => Sem r ()
runTests = do
  -- :: Either String (Frame Packet)
  frame1 <- loadPcapIntoFrame defaultTsharkPrefs "examples/client_2_cleaned.pcapng"

  (aframe :: FrameFiltered TcpConnection Packet) <- case buildFrameFromStreamId (fromRight (error "should not happen") frame1) (StreamId 0) of
    Left err -> error err
    Right aframe -> return aframe

  -- TODO run hspec and check FrameLength is the same ?
  -- check stats over the whole file
  P.embed $ hspec $ do
    describe "absolute" $ do
      it "Check generated stats" $
        -- pendingWith "test"
          getTcpStats aframe RoleServer == expectedForwardStats
          getTcpStats aframe RoleClient == expectedBackwardStats

      it "Test append of stats" $
          expectedForwardStats0 <> expectedForwardStats1 == expectedForwardStatsTotal01
  return ()

  -- hspec $ do
  --   describe "absolute" $ do
  --     it "returns the original number when given a positive input" $
  --       -- TODO check
  --       computeStats aframe `equal` computeStats [aframes]

        -- numberToTcpFlags 2 `shouldBe` [TcpFlagSyn]

