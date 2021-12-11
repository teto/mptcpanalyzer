{-# LANGUAGE OverloadedStrings #-}

module Net.Tcp.Connection (
    TcpConnection(..)
  , TcpConnectionOriented(..)
  , tcpConnectionToOriented
  , showTcpConnectionText
  , reverseTcpConnectionTuple
  , tcpConnectionfromOriented
)
where
import Data.Text as TS
import Data.Word (Word16, Word32, Word64, Word8)
import MptcpAnalyzer.Stream
import Net.IP

-- | Identifies a TCP connection
-- TODO TcpTsharkConnection
data TcpConnection = TcpConnection {
  -- TODO use libraries to deal with that ? filter from the command line for instance ?
    conTcpClientIp :: IP -- ^Client ip
  , conTcpServerIp :: IP -- ^Server ip
  , conTcpClientPort :: Word16  -- ^ Source port
  , conTcpServerPort :: Word16  -- ^Destination port
  -- Could be a maybe ?
  , conTcpStreamId :: StreamIdTcp -- ^ @tcp.stream@ in wireshark
  } deriving (Show, Eq, Ord)


-- |
data TcpConnectionOriented = TcpConnectionOriented {
    conTcpSourceIp :: IP -- ^Source ip
  , conTcpDestinationIp :: IP -- ^Destination ip
  , conTcpSourcePort :: Word16  -- ^ Source port
  , conTcpDestinationPort :: Word16  -- ^Destination port
  } deriving (Show, Eq, Ord)


reverseTcpConnectionTuple :: TcpConnectionOriented -> TcpConnectionOriented
reverseTcpConnectionTuple con = TcpConnectionOriented {
    conTcpSourceIp = conTcpDestinationIp con
  , conTcpDestinationIp = conTcpSourceIp con
  , conTcpSourcePort = conTcpDestinationPort con
  , conTcpDestinationPort = conTcpSourcePort con
  }


-- | Uses the source as client. Use 'reverseTcpConnectionTuple' to assign the server as source
tcpConnectionfromOriented ::
     TcpConnectionOriented
  -- ^ Source is the client
  -> TcpConnection
tcpConnectionfromOriented tup = TcpConnection {

    conTcpClientIp = conTcpSourceIp tup
  , conTcpServerIp = conTcpDestinationIp tup
  , conTcpClientPort = conTcpSourcePort tup
  , conTcpServerPort = conTcpDestinationPort tup
  , conTcpStreamId = StreamId 0
  }

tcpConnectionToOriented ::
     TcpConnection
  -- ^ Source is the client
  -> TcpConnectionOriented
tcpConnectionToOriented con = TcpConnectionOriented {

    conTcpSourceIp = conTcpClientIp con
  , conTcpDestinationIp = conTcpServerIp con
  , conTcpSourcePort = conTcpClientPort con
  , conTcpDestinationPort = conTcpServerPort con
  }



tshow :: Show a => a -> TS.Text
tshow = TS.pack . Prelude.show

-- | Pretty print
showTcpConnectionText :: TcpConnection -> Text
showTcpConnectionText con =
  showIp (conTcpClientIp con) <> ":" <> tshow (conTcpClientPort con) <> " -> "
      <> showIp (conTcpServerIp con) <> ":" <> tshow (conTcpServerPort con)
      <> " (tcp.stream: " <> showStream (conTcpStreamId con) <> ")"
  where
    showIp = Net.IP.encode
    showStream (StreamId a) = tshow a
