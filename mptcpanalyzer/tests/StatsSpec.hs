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
import Tshark.Main (defaultTsharkPrefs)
import Frames
import Data.Either (fromRight)
import MptcpAnalyzer.Stream

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
        pendingWith "test"

  return ()

  -- hspec $ do
  --   describe "absolute" $ do
  --     it "returns the original number when given a positive input" $
  --       -- TODO check
  --       computeStats aframe `equal` computeStats [aframes]

        -- numberToTcpFlags 2 `shouldBe` [TcpFlagSyn]

