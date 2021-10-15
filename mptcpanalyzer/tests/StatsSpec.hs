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
import           Test.Hspec
import           Test.QuickCheck                    hiding (Success)
import           MptcpAnalyzer.Pcap
import           MptcpAnalyzer.Loader
import           Frames.Exploration

import Polysemy (Sem, Members, runFinal, Final)
import qualified Polysemy as P
import qualified Polysemy.IO as P
import qualified Polysemy.State as P
import qualified Polysemy.Embed as P
import qualified Polysemy.Internal as P
import qualified Polysemy.Trace as P
import Polysemy.Log (Log)
import qualified Polysemy.Log as Log
import Polysemy.Log.Colog (interpretLogStdout)
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Types
import Net.Tcp

-- import           MptcpAnalyzer.Stats



cacheConfig :: CacheConfig
cacheConfig = CacheConfig {
  cacheFolder = "/tmp"
  , cacheEnabled = False
}

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
  -- frame1 <- loadPcapIntoFrame defaultTsharkPrefs "examples/client_2_cleaned.pcapng"

  -- let aframe = case buildFrameFromStreamId (fromRight undefined frame1) (StreamId 0) of
  --   Left err -> error err
  --   Right aframe -> aframe
  return ()

  -- hspec $ do
  --   describe "absolute" $ do
  --     it "returns the original number when given a positive input" $
  --       -- TODO check
  --       computeStats aframe `equal` computeStats [aframes]

        -- numberToTcpFlags 2 `shouldBe` [TcpFlagSyn]

