{-|
Module      : MptcpAnalyzer.Stats
Description : Compute statistics on connections
Maintainer  : matt
License     : GPL-3
-}

module MptcpAnalyzer.Stats (
    -- getTcpStats
  -- , getMptcpStats
  -- , getSubflowStats
  )
where

import MptcpAnalyzer.ArtificialFields
import MptcpAnalyzer.Frame
import MptcpAnalyzer.Types
import Net.Mptcp
import Net.Tcp
import Tshark.Fields


import Control.Lens hiding (argument)
import qualified Data.Foldable as F
import qualified Data.Map as Map
import Data.Ord (comparing)
import Data.Word (Word32, Word64)
import Frames
import qualified Frames as F
import qualified Frames.InCore as F
import MptcpAnalyzer.Pcap

-- TODO should be able to update an initial one
-- type Packet = Record HostCols
