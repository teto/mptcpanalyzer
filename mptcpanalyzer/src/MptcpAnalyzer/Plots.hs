module MptcpAnalyzer.Plots
(
  -- module MptcpAnalyzer.Plots.Stream
)
where

import MptcpAnalyzer.Plots.Stream
import MptcpAnalyzer.Types


-- connectionToLabel :: Connection -> String
-- connectionToLabel con@TcpConnection{} =
--   showIp (con.clientIp) <> ":" <> tshow (con.clientPort) <> " -> "
--       <> showIp (con.serverIp) <> ":" <> tshow (con.serverPort)
--       <> "  (tcp.stream: " <> tshow (streamId con) <> ")"
--   where
--     showIp = Net.IP.encode

-- plotTcpSeq ::
--         plot (line ("TCP " ++ field ++ " (" ++ show dest ++ ")") [ [ (d,v) | (d,v) <- zip timeData seqData ] ])

