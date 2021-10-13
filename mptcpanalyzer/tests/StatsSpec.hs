haskell-{-
Module:  StatsSpec
Description :  Description
Maintainer  : matt
Portability : Linux

Load a pcap in chunks and check that it produces the same result
-}
module StatsSpec where
-- import           Test.Tasty
-- import           Test.Tasty.HUnit
import           Test.Hspec
import           Test.QuickCheck                    hiding (Success)
import           MptcpAnalyzer.Pcap
import           MptcpAnalyzer.Loader
import           Frames.Exploration

-- 
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


splitAFrame :: FrameFiltered TcpConnection HostCols -> Int -> [FrameFiltered TcpConnection HostCols]
splitAFrame aframe chunkSize  =
  -- takeRows / dropRow
  go frame []
  where
    go aframe' acc = if frameLength (ffFrame aframe') < chunkSize then
        acc ++ aframe'
      else
        acc
        ++ (FrameTcp (ffCon aframe') (takeRows chunkSize $ ffFrame aframe'))
        ++ go (FrameTcp (ffCon aframe') (dropRows chunkSize $ ffFrame aframe'))


runTests :: (Members '[P.Embed IO, Log , Cache] r) => Sem r ()
runTests = do

  frame1 <- loadPcapIntoFrame defaultTsharkPrefs "examples/client_2_cleaned.pcapng"

  let aframe = case buildFrameFromStreamId (fromRight undefined frame1) (StreamId 0) of
    Left err -> error err
    Right aframe -> aframe

  hspec $ do
    describe "absolute" $ do
      it "returns the original number when given a positive input" $
        -- TODO check
        computeStats aframe `equal` computeStats [aframes]

        numberToTcpFlags 2 `shouldBe` [TcpFlagSyn]

