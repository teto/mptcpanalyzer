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
import qualified Data.HashMap.Strict         as HM
import qualified Commands.Utils         as CMD

import Options.Applicative


data LoadPcap = LoadPcap {
  pcap :: FilePath
}

loadPcapParser :: Parser LoadPcap
loadPcapParser = LoadPcap
      -- TODO complete with filepath
      <$> argument str (metavar "PCAP" <> completeWith ["toto", "tata"]
          <> help "Target for the greeting"
      )

-- TODO move commands to their own module
-- TODO it should update the loadedFile in State !
cmdLoad :: (CommandConstraint m) => [String] -> m ()
cmdLoad pcapFile = do
    $(logTM) DebugS "starting"
    args <- execParser
    mFrame <- loadPcap defaultTsharkPrefs pcapFile
    return ()


-- loadRows :: IO (PcapFrame)
-- loadRows = inCoreAoS (readTable "data/server_2_filtered.pcapng.csv")

