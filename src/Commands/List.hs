module Commands.List
where

import Data.Text
import Net.Tcp



newtype MptcpStreamId = Int
newtype TcpStreamId = Int

-- This 
data ParserListSubflows = ParserListSubflows {
  full :: Bool,
  streamId :: MptcpStreamId
}

-- |TODO pass the loaded pcap to have a complete filterWith
-- listSubflowParser = 

parser :: Parser ParserListSubflows
parser = Parser <$> (switch
          ( long "full"
         <> help "Print details for each subflow" ))
      <*> argument (
          long "version"
          <> help "Show version"
          -- TODO pass a default
          )

opts :: ParserInfo ListSubflows
opts = info (sample <**> helper)
  ( fullDesc

  <> progDesc "List subflows of an MPTCP connection"
  <> header ""
  <> footer ""
  )

-- listTcpConnections :: [TcpConnection] -> Text
-- listTcpConnections conns =
--         streams = self.data.groupby("tcpstream")
--         (show len connections) ++ " tcp connection(s)" ++ map (\
--         where
          -- for tcpstream, group in streams:
          --     con = TcpConnection.build_from_dataframe(self.data, tcpstream)
          --     self.poutput(str(con))

