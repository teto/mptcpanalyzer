module MptcpAnalyzer.Plots
(
  -- module MptcpAnalyzer.Plots.Stream
)
where

import MptcpAnalyzer.Plots.Stream
import MptcpAnalyzer.Types


-- connectionToLabel :: Connection -> String
-- connectionToLabel con@TcpConnection{} =
--   showIp (conTcpClientIp con) <> ":" <> tshow (conTcpClientPort con) <> " -> "
--       <> showIp (conTcpServerIp con) <> ":" <> tshow (conTcpServerPort con)
--       <> "  (tcp.stream: " <> tshow (conTcpStreamId con) <> ")"
--   where
--     showIp = Net.IP.encode
