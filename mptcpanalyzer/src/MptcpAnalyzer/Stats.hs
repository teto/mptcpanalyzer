{-|
Module      : MptcpAnalyzer.Stats
Description : Compute statistics on connections
Maintainer  : matt
License     : GPL-3
-}

module MptcpAnalyzer.Stats (
  getTcpStats
  , getMptcpStats
  , getSubflowStats
  )
where

import Net.Tcp
import Net.Mptcp
import MptcpAnalyzer.Frame
import Tshark.Fields
import MptcpAnalyzer.Types
import MptcpAnalyzer.ArtificialFields


import Frames
import qualified Frames as F
import qualified Frames.InCore as F
import qualified Data.Foldable as F
import Control.Lens hiding (argument)
import MptcpAnalyzer.Pcap
import Data.Word (Word32, Word64)
import Data.Ord (comparing)
import qualified Data.Map as Map

-- TODO should be able to update an initial one
-- type Packet = Record HostCols
