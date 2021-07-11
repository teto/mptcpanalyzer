module MptcpAnalyzer.Commands.Export
where

import MptcpAnalyzer.Types
import MptcpAnalyzer.Commands.Definitions
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Pcap

import Control.Lens ((^.), view)
import Prelude hiding (log)
import Polysemy (Sem, Members, Embed)
import Polysemy.State as P
import Frames.CSV (writeCSV)
import Options.Applicative

parseExportOpts ::  ParserInfo CommandArgs
parseExportOpts = info (
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
