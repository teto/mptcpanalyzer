module MptcpAnalyzer.Plots.Types (
  PlotSettings(..)
  , ArgsPlots(..)

)
where

import MptcpAnalyzer.Types
import MptcpAnalyzer.Stream
import MptcpAnalyzer.ArtificialFields
import Data.Word (Word32)
import Net.IP
import Net.Tcp

-- | Settings shared by all plots
data PlotSettings = PlotSettings {
  -- | Where to save the file
  plsOut :: Maybe String
  -- | To override the default title
  , plsTitle :: Maybe String
  -- | Whether to display the result
  , plsDisplay :: Bool
  -- , ploLabelx :: String
  -- , ploLabely :: String
  , plsMptcp :: Bool -- ^ True if it's an mptcp plot (as opposed to TCP)
  }
      -- parser.add_argument('--display', action="store", default="term", choices=["term", "gui", "no"],

data ArgsPlots =

    -- actually valid for MPTCP too
    -- | Expects a filename/streamId attr and maybe destination
    ArgsPlotTcpAttr FilePath Word32 String (Maybe ConnectionRole)
    -- |
    -- @pcap1 pcap2 stream1 stream2 destinations whether its tcp or mptcp
    | ArgsPlotOwdTcp (PcapMapping Tcp) (Maybe ConnectionRole)
    | ArgsPlotOwdMptcp (PcapMapping Mptcp) (Maybe ConnectionRole)
    | ArgsPlotLiveTcp TcpConnection (Maybe ConnectionRole) String -- ^Interface name
