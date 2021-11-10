module MptcpAnalyzer.Commands.Export (
  piExportOpts
  , cmdExport
)
where

import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Types

import Control.Lens (view, (^.))
import Frames.CSV (writeCSV)
import Options.Applicative
import Polysemy (Embed, Members, Sem)
import Polysemy.State as P
import Prelude hiding (log)

piExportOpts ::  ParserInfo CommandArgs
piExportOpts = info (
   ArgsExport <$> parserList <**> helper)
  ( progDesc "Filename to export to"
  )
  where
    -- _exportFilename
    parserList = argument str (metavar "PCAP" <> completeWith ["toto", "tata"]
          <> help "Load a Csv file"
      )

{-| Export loaded file
-}
cmdExport :: Members '[P.State MyState, Cache, Embed IO] r
    => FilePath
    -> Sem r RetCode
cmdExport args = do
  state <- P.get
  return Continue
  -- let loadedPcap = view loadedFile state
  -- fmap writeToCSV loadedPcap >>= \case
  --   Just True -> return Continue
  --   _ -> return $ Error "test"
  -- where
  --   writeToCSV frame = writeCSV (_exportFilename args) frame >> return True
