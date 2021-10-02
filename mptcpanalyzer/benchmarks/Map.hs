{-# LANGUAGE QuasiQuotes,
             DataKinds,
             FlexibleContexts,
             TypeApplications,
             TemplateHaskell #-}

import MptcpAnalyzer.Map
import Criterion.Main
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Loader (loadPcapIntoFrame)
import MptcpAnalyzer.Pcap (buildFrameFromStreamId, defaultTsharkPrefs)

import Polysemy (Sem, Members, runFinal, Final)
import qualified Polysemy as P
import qualified Polysemy.IO as P
import qualified Polysemy.State as P
import qualified Polysemy.Embed as P
import qualified Polysemy.Internal as P

import Polysemy.Log (Log)
import qualified Polysemy.Log as Log
import Polysemy.Log.Colog (interpretLogStdout)
import MptcpAnalyzer.Stream
import Control.Monad.IO.Class (liftIO)
import Data.Either (fromRight)

-- tableTypes "LCols" "data/left1.csv"
-- tableTypes "RCols" "data/right1.csv"
-- tableTypes "SmCols" "data/left_summary.csv"

-- lfi :: IO (Frame LCols)
-- lfi = inCoreAoS (readTable "data/left1.csv")

-- rfi :: IO (Frame RCols)
-- rfi = inCoreAoS (readTable "data/right1.csv")

-- smfi :: IO (Frame SmCols)
-- smfi = inCoreAoS (readTable "data/left_summary.csv")
cacheConfig :: CacheConfig
cacheConfig = CacheConfig {
  cacheFolder = "/tmp"
  , cacheEnabled = True
}

-- logs/cache
main :: IO ()
main = do

  --  P.runEmbedded liftIO @IO
  _ <- P.runM 
    $ interpretLogStdout
    $ runCache cacheConfig
      inputLoop 
  putStrLn "finished"


inputLoop :: (Members '[P.Embed IO, Log , Cache] r) => Sem r ()
inputLoop = do
  frame1 <- loadPcapIntoFrame defaultTsharkPrefs "examples/client_2_cleaned.pcapng"
  frame2 <- loadPcapIntoFrame defaultTsharkPrefs "examples/server_2_cleaned.pcapng"

  case buildFrameFromStreamId (fromRight undefined frame1) (StreamId 0) of
    Left err -> error err
    Right aframe -> P.embed $ defaultMain [
      bench "inner1a" $ nf (\x -> mapTcpConnection aframe x >> pure () ) (fromRight (error "could not load frame 1")  frame2)
      ]


