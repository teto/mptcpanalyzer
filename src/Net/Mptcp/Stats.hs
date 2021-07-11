module Net.Mptcp.Stats
where

import MptcpAnalyzer.ArtificialFields
-- import MptcpAnalyzer.Types
-- import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Stream
import Net.Tcp
import Net.Mptcp.Connection
import qualified Data.Map as Map


import Control.Lens hiding (argument)
import Data.Word (Word32, Word64)
import Data.Maybe (fromJust)
import qualified Frames as F
import qualified Data.Foldable as F
import Data.List (sort, sortBy, sortOn)
import Data.Map (Map, fromList, mapKeys)
import qualified Data.Map as Map
import Control.Lens

-- | Useful to show DSN
data TcpSubflowUnidirectionalStats = TcpSubflowUnidirectionalStats {
  -- tssStats :: TcpUnidirectionalStats
  tssStats :: TcpUnidirectionalStats
  -- tss
  -- add DSN stats

  }
-- newtype TcpSubflowUnidirectionalStats = TcpSubflowUnidirectionalStats


-- | Holds MPTCP statistics for one direction
data MptcpUnidirectionalStats = MptcpUnidirectionalStats {
  musDirection :: ConnectionRole
  , musApplicativeBytes :: Word64
  , musMaxDsn :: Word64
  , musMinDsn :: Word64
  , musSubflowStats :: Map MptcpSubflow TcpSubflowUnidirectionalStats
  }


    -- ''' application data = goodput = useful bytes '''
    -- ''' max(dsn)- min(dsn) - 1'''
    -- mptcp_application_bytes: Byte

    -- '''Total duration of the mptcp connection'''
    -- mptcp_duration: datetime.timedelta
    -- subflow_stats: List[TcpUnidirectionalStats]

    -- @property
    -- def mptcp_throughput_bytes(self) -> Byte:
    --     ''' sum of total bytes transferred '''
    --     return Byte(sum(map(lambda x: x.throughput_bytes, self.subflow_stats)))

-- undefined
getMptcpGoodput :: MptcpUnidirectionalStats -> Double
getMptcpGoodput s = fromIntegral (musApplicativeBytes s) / ((getMptcpStatsDuration s) ^. _1)


-- | return max - min across subflows
getMptcpStatsDuration :: MptcpUnidirectionalStats -> (Double, Double, Double)
getMptcpStatsDuration s = (end - start, start, end)
  where
    start = head $ sort starts
    end = last $ sort ends
    -- min of
    -- TODO get min
    starts = map (tusStartTime . tssStats) (Map.elems $ musSubflowStats s)
    -- take the maximum
    ends = map (tusEndTime . tssStats) (Map.elems $ musSubflowStats s)
