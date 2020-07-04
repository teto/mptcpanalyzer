-- load pcap
{-# LANGUAGE DataKinds, FlexibleContexts, QuasiQuotes, TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
import Frames
-- import Frames.CSV
import           Frames.TH                      ( rowGen
                                                , RowGen(..)
                                                )

-- tableTypes is a Template Haskell function, which means that it is executed at compile time. It generates a data type for our CSV, so we have everything under control with our types.
-- tableTypes "Packet" "data/server_2_filtered.pcapng.csv"

tableTypes' (rowGen "data/server_2_filtered.pcapng.csv")
            { rowTypeName = "NoH"
            , columnNames = [ "Job", "Schooling", "Money", "Females"
                            , "Respect", "Census", "Category" ]
            , tablePrefix = "NoHead"}



loadRows :: IO (Frame Packet)
loadRows = inCoreAoS (readTable "data/server_2_filtered.pcapng.csv")
