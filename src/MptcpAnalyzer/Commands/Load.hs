{-# LANGUAGE DataKinds, FlexibleContexts, QuasiQuotes, TemplateHaskell #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
module MptcpAnalyzer.Commands.Load
where
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Loader
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Types
-- import Control.Lens hiding (argument)

import Frames
import Options.Applicative
import Control.Monad.Trans (liftIO)
import Distribution.Simple.Utils (withTempFileEx, TempFileOptions(..))
import System.Exit (ExitCode(..))
-- import Prelude hiding (log)
import Polysemy (Sem, Members, Embed)
import qualified Polysemy.State as P
import qualified Polysemy.Trace as P
import Polysemy.Log (Log)
import qualified Polysemy.Log as Log

loadPcapArgs :: Parser CommandArgs
loadPcapArgs =  ArgsLoadPcap <$> argument str (metavar "PCAP" <> completeWith ["toto", "tata"]
          <> help "Load a Pcap file"
      )

loadCsvArgs :: Parser CommandArgs
loadCsvArgs =  ArgsLoadCsv <$> argument str (metavar "PCAP" <> completeWith ["toto", "tata"]
          <> help "Load a Csv file"
      )

piLoadCsv :: ParserInfo CommandArgs
piLoadCsv = info (loadCsvArgs <**> helper)
  ( fullDesc
  <> progDesc "Load a csv file generated from wireshark"
  )

loadPcapOpts :: ParserInfo CommandArgs
loadPcapOpts = info (loadPcapArgs <**> helper)
  ( fullDesc
  <> progDesc "Load a pcap file via wireshark"
  <> footer "Example: load-pcap examples/client_2_filtered.pcapng"
  )


-- myHandleParseResult :: ParserResult a -> m CMD.RetCode
-- myHandleParseResult (Success a) = 



loadCsv :: (Members '[Log, P.Trace, P.State MyState, Cache, Embed IO] m)
    => FilePath   -- ^ csv file to load
    -> Sem m CMD.RetCode
loadCsv csvFilename  = do

    P.trace $ "Loading " ++ csvFilename
    frame <- liftIO $ loadRows csvFilename
    -- TODO restore
    -- loadedFile .= Just frame
    P.modify (\s -> s { _loadedFile = Just frame })
    Log.info $ "Number of rows " <> tshow  (frameLength frame)
    Log.debug "Frame loaded" >> return CMD.Continue

