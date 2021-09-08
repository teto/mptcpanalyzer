{-# LANGUAGE QuasiQuotes,
             DataKinds,
             FlexibleContexts,
             TypeApplications,
             TemplateHaskell #-}

import MptcpAnalyzer.Map
import Criterion.Main

-- tableTypes "LCols" "data/left1.csv"
-- tableTypes "RCols" "data/right1.csv"
-- tableTypes "SmCols" "data/left_summary.csv"

-- lfi :: IO (Frame LCols)
-- lfi = inCoreAoS (readTable "data/left1.csv")

-- rfi :: IO (Frame RCols)
-- rfi = inCoreAoS (readTable "data/right1.csv")

-- smfi :: IO (Frame SmCols)
-- smfi = inCoreAoS (readTable "data/left_summary.csv")

main :: IO ()
main = do
  -- lf <- lfi
  -- rf <- rfi
  -- smf <- smfi
  frame1 <- loadPcapIntoFrame defaultTsharkPrefs "examples/client_2_cleaned.pcapng"
  frame2 <- loadPcapIntoFrame defaultTsharkPrefs "examples/server_2_cleaned.pcapng"

  let aframe = buildFrameFromStreamId  frame1 (StreamId 0)
  -- mapTcpConnection 
  -- mapMptcpConnection 

  defaultMain [
    bench "inner1a" $ mapTcpConnection aframe frame2
    ]

