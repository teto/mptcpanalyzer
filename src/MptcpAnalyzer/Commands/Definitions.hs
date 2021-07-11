module MptcpAnalyzer.Commands.Definitions
where
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Types
import MptcpAnalyzer.Stream
import MptcpAnalyzer.Plots.Types

import Data.Word (Word32)
import Options.Applicative

-- import Polysemy (Sem, Members, makeSem, interpret, Effect)

-- | To reprensent a mapping between 2 pcaps
-- data PcapMapping a = PcapMapping {
--       pmapPcap1 :: FilePath
--       , pmapStream1 :: StreamId a
--       , pmapPcap2 :: FilePath
--       , pmapStream2 :: StreamId a
--       -- , pmapVerbose :: Bool
--       -- , pmapLimit :: Int -- ^Number of comparisons to show
--       -- , pmapMptcp :: Bool -- ^Wether it's an MPTCP
--     }

data CommandMapPcap = CommandMapPcap {
  argsMapPcap1 :: FilePath
  , argsMapPcap2 :: FilePath
  , argsMapStream :: Word32
  , argsMapVerbose :: Bool
  , argsMapLimit :: Int -- ^Number of comparisons to show
  -- , argsMapMptcp :: Bool -- ^Wether it's an MPTCP
}

-- | Registered commands
-- TODO make it possible to add some from a plugin
data CommandArgs =
    ArgsLoadCsv FilePath
    | ArgsHelp
    | ArgsQuit
    | ArgsLoadPcap FilePath
    | ArgsListTcpConnections Bool  -- ^ Detailed
    | ArgsListMpTcpConnections Bool  -- ^ Detailed
    | ArgsMapTcpConnections CommandMapPcap Bool
    -- ^ Pcap 1 Pcap 2 streamId1 verbose Limit Mptcp
    -- | ArgsMapMptcpConnections FilePath FilePath Word32 Bool Int Bool
    | ArgsListSubflows Bool
      -- ^ _listSubflowsDetailed
    | ArgsListReinjections (StreamId Mptcp)
    | ArgsParserSummary Bool (StreamId Tcp)
    | ArgsMptcpSummary Bool (StreamId Mptcp)
    | ArgsExport FilePath   -- ^ argsExportFilename
    -- | plotOut
    -- Bool Whether we have to display
    -- Bool Whether it's TCP
    | ArgsPlotGeneric PlotSettings ArgsPlots
    | ArgsQualifyReinjections (PcapMapping Mptcp) Bool

-- | Return code for user command. Whether to exit program or keep going
data RetCode = Exit | Error String | Continue

parserPcapMapping :: Bool -> Parser (PcapMapping a)
parserPcapMapping forMptcp =
  -- if forMptcp then
    PcapMapping <$>
  -- else
  --   ArgsMapMptcpConnections <$> toto
  -- where
  -- toto =
      strArgument (
          metavar "PCAP1"
          <> help "File to analyze"
      )
      <*> argument readStreamId (
          metavar "TCP_STREAM"
          <> help "stream id to analyzer"
      )
      <*> strArgument (
          metavar "PCAP2"
          <> help "File to analyze"
      )
      -- 
      <*> argument readStreamId (
          metavar "TCP_STREAM"
          <> help "stream id to analyzer"
      )
