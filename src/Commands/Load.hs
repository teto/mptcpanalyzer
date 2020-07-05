{-# LANGUAGE DataKinds, FlexibleContexts, QuasiQuotes, TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
module Commands.Load
where
import Frames
-- import Frames.CSV
import Pcap
import           Frames.TH                      ( rowGen
                                                , RowGen(..)
                                                )





loadRows :: IO (PcapFrame)
loadRows = inCoreAoS (readTable "data/server_2_filtered.pcapng.csv")


