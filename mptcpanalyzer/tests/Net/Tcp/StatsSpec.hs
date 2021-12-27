{-# LANGUAGE ScopedTypeVariables #-}
{-
Module:  StatsSpec
Description :  Description
Maintainer  : matt
Portability : Linux

Load a pcap in chunks and check that it produces the same result
-}
module Net.Tcp.StatsSpec (
  spec
) where
import Frames.Exploration
-- import MptcpAnalyzer.Loader
import MptcpAnalyzer.Pcap
import Test.Hspec
-- import Test.QuickCheck hiding (Success)

-- import Data.Either (fromRight)
-- import Frames
import MptcpAnalyzer.ArtificialFields
-- import MptcpAnalyzer.Cache
-- import MptcpAnalyzer.Stream
import MptcpAnalyzer.Types
import Net.Tcp
import Net.Tcp.Stats
-- import Polysemy (Final, Members, Sem, runFinal)
-- import qualified Polysemy as P
-- import qualified Polysemy.Embed as P
-- import qualified Polysemy.IO as P
-- import qualified Polysemy.Internal as P
-- import Polysemy.Log (Log)
-- import qualified Polysemy.Log as Log
-- import Polysemy.Log.Colog (interpretLogStdout)
-- import qualified Polysemy.State as P
-- import qualified Polysemy.Trace as P
-- import Tshark.Main (defaultTsharkPrefs)
import Utils
import Data.Foldable (foldl')
import Net.Stream

-- cacheConfig :: CacheConfig
-- cacheConfig = CacheConfig {
--   cacheFolder = "/tmp"
--   , cacheEnabled = False
-- }

expectedForwardStats, expectedForwardStats0, expectedForwardStats1 :: TcpUnidirectionalStats
expectedBackwardStats, expectedBackwardStats0, expectedForwardStatsTotal01  :: TcpUnidirectionalStats
expectedForwardStats = mempty
expectedBackwardStats = mempty
expectedForwardStats0 = TcpUnidirectionalStats {tusNrPackets = 16, tusStartTime = 0.0, tusEndTime = 45.831181697, tusMinSeq = 0, tusSndUna = 457, tusSndNext = 457, tusReinjectedBytes = 0}
expectedForwardStats1 = mempty
expectedBackwardStats0 = TcpUnidirectionalStats {tusNrPackets = 13, tusStartTime = 0.184116349, tusEndTime = 45.842675096, tusMinSeq = 0, tusSndUna = 309, tusSndNext = 309, tusReinjectedBytes = 0}
expectedForwardStatsTotal01 = mempty

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

-- loadAFrame :: IO (FrameFiltered TcpConnection Packet)
-- loadAFrame = do

--   aframe <- P.runM
--     $ interpretLogStdout
--     $ runCache cacheConfig
--       runTests
--   return aframe
--   putStrLn "finished"




-- runTests :: (Members '[P.Embed IO, Log , Cache] r) => Sem r (FrameFiltered TcpConnection Packet)
-- runTests = do
--   -- :: Either String (Frame Packet)
--   frame1 <- loadPcapIntoFrame defaultTsharkPrefs "examples/client_2_cleaned.pcapng"

--   (aframe :: FrameFiltered TcpConnection Packet) <- case buildFrameFromStreamId (fromRight (error "should not happen") frame1) (StreamId 0) of
--     Left err -> error err
--     Right aframe -> return aframe

--   return aframe

  -- TODO run hspec and check FrameLength is the same ?
  -- check stats over the whole file
  -- P.embed $ hspec $


expectedStats :: TcpUnidirectionalStats
-- expectedStats = mempty
expectedStats = TcpUnidirectionalStats {tusNrPackets = 13, tusStartTime = 0.0, tusEndTime = 45.842675096, tusMinSeq = 0, tusSndUna = 0, tusSndNext = 0, tusReinjectedBytes = 0}

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



-- beforeWith (loadAFrame) $
-- before loadAFrame $ describ
spec :: Spec
spec = before (loadAFrame "examples/client_2_cleaned.pcapng" (StreamId 0)) $
      describe "Checking stats" $ do
        it "Check generated forward stats" $ \aframe ->
          getTcpStatsFromAFrame (addTcpDestinationsToAFrame aframe) RoleServer `shouldBe` expectedForwardStats0
        it "Check generated backwards stats" $ \aframe ->
          getTcpStatsFromAFrame (addTcpDestinationsToAFrame aframe) RoleClient `shouldBe` expectedBackwardStats0

        it "Processing stats in chunks equal processing the full batch" $ \aframe -> let 
            chunks = splitAFrame aframe 2
          in
            foldl' (\origStats newAframe -> origStats <> getTcpStatsFromAFrame (addTcpDestinationsToAFrame newAframe) RoleClient ) mempty chunks `shouldBe` expectedStats

        -- it "Checking two crafted stats" $ \aframe -> let 

  -- it "Test append of stats" $
  --     expectedForwardStats0head <> expectedForwardStats0tail `shouldBe` expectedForwardStats0
  -- pendingWith "test"

